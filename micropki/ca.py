
from .audit import init_audit_log, log_audit
from .transparency import init_ct_log, log_certificate_to_ct
from .policy import validate_key_size, validate_validity_days, validate_san_types
from .compromise import is_key_compromised, mark_key_compromised, init_compromised_table
import logging
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID

from . import crypto_utils
from . import certificates
from . import csr as csr_module
from . import templates
from .database import insert_certificate, update_certificate_status, get_certificate_by_serial
from .revocation import validate_reason, revoke_certificate
from .serial import generate_serial, serial_to_hex

from .policy import validate_key_size, validate_validity_days, validate_san_types
from .audit import init_audit_log, log_audit
from .transparency import init_ct_log, log_certificate_to_ct
from .compromise import is_key_compromised
logger = logging.getLogger(__name__)


def _get_common_name(name: x509.Name) -> str:
    """Extract CN from DN."""
    cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn_attrs[0].value if cn_attrs else None


def _policy_content(cert, args):
    return f"""Certificate Policy for MicroPKI Root CA
===================================
CA Name (Subject): {cert.subject.rfc4514_string()}
Certificate Serial Number (hex): {format(cert.serial_number, 'X')}
Validity Period:
  Not Before: {cert.not_valid_before_utc.isoformat()}
  Not After : {cert.not_valid_after_utc.isoformat()}
Key Algorithm: {args.key_type.upper()}-{args.key_size}
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: {datetime.now(timezone.utc).isoformat()}
"""


def init_ca(args):
    """Initialize self-signed Root CA with audit and policy."""
    from .audit import init_audit_log, log_audit
    from .transparency import init_ct_log, log_certificate_to_ct
    from .policy import validate_key_size, validate_validity_days

    out_dir = Path(args.out_dir).resolve()

    # Initialise audit and CT logs
    init_audit_log(out_dir)
    ct_path = init_ct_log(out_dir)

    # Validate policy
    cert_type = 'root'
    key_type = args.key_type
    key_size = args.key_size

    valid, msg = validate_key_size(key_size, cert_type, key_type)
    if not valid:
        log_audit("AUDIT", "ca_init", "failure", msg, {"subject": args.subject})
        raise ValueError(msg)

    valid, msg = validate_validity_days(args.validity_days, cert_type)
    if not valid:
        log_audit("AUDIT", "ca_init", "failure", msg, {"subject": args.subject})
        raise ValueError(msg)

    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    private_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)

    passphrase_file = Path(args.passphrase_file)
    if not passphrase_file.is_file():
        raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")
    passphrase = crypto_utils.load_passphrase(passphrase_file)

    if args.key_type == 'rsa':
        private_key = crypto_utils.generate_rsa_key(args.key_size)
    else:
        private_key = crypto_utils.generate_ecc_key()

    key_pem = crypto_utils.encrypt_private_key(private_key, passphrase)
    key_path = private_dir / 'ca.key.pem'
    crypto_utils.save_pem(key_pem, key_path, mode=0o600)
    logger.info(f"Encrypted private key saved to {key_path}")

    subject = certificates.parse_dn(args.subject)

    db_path = Path(args.db_path) if hasattr(args, 'db_path') and args.db_path else out_dir / 'micropki.db'
    if db_path.exists():
        serial_int = generate_serial(db_path)
    else:
        serial_int = int.from_bytes(os.urandom(20), byteorder='big')
    serial_hex = serial_to_hex(serial_int)

    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(serial_int)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    hash_algo = hashes.SHA256() if args.key_type == 'rsa' else hashes.SHA384()
    cert = builder.sign(private_key=private_key, algorithm=hash_algo)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path = certs_dir / 'ca.cert.pem'
    cert_path.write_bytes(cert_pem)
    logger.info(f"Certificate saved to {cert_path}")

    if db_path.exists():
        cert_data = {
            'serial_hex': serial_hex,
            'subject': subject.rfc4514_string(),
            'issuer': subject.rfc4514_string(),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'cert_pem': cert_pem.decode('utf-8'),
            'status': 'valid',
            'created_at': now.isoformat()
        }
        insert_certificate(db_path, cert_data)

    policy_path = out_dir / 'policy.txt'
    policy_path.write_text(_policy_content(cert, args))
    logger.info(f"Policy document saved to {policy_path}")

    # Audit log
    log_audit("AUDIT", "ca_init", "success",
              f"Root CA initialised for {args.subject}",
              {"subject": args.subject, "serial": serial_hex, "key_type": key_type, "key_size": key_size})

    # CT log
    log_certificate_to_ct(ct_path, cert, subject.rfc4514_string())

    logger.info("Root CA initialisation successful")


def issue_intermediate(args):
    """Create and sign an Intermediate CA certificate."""
    out_dir = Path(args.out_dir).resolve()
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    csrs_dir = out_dir / 'csrs'
    private_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    csrs_dir.mkdir(parents=True, exist_ok=True)

    root_cert = x509.load_pem_x509_certificate(Path(args.root_cert).read_bytes())
    root_pass = crypto_utils.load_passphrase(Path(args.root_pass_file))
    root_key = crypto_utils.load_encrypted_private_key(Path(args.root_key), root_pass)

    if args.key_type == 'rsa':
        inter_key = crypto_utils.generate_rsa_key(args.key_size)
    else:
        inter_key = crypto_utils.generate_ecc_key()

    inter_pass = crypto_utils.load_passphrase(Path(args.passphrase_file))
    inter_key_pem = crypto_utils.encrypt_private_key(inter_key, inter_pass)
    inter_key_path = private_dir / 'intermediate.key.pem'
    crypto_utils.save_pem(inter_key_pem, inter_key_path, mode=0o600)
    logger.info(f"Intermediate CA key saved to {inter_key_path}")

    subject = certificates.parse_dn(args.subject)

    db_path = Path(args.db_path) if hasattr(args, 'db_path') and args.db_path else out_dir / 'micropki.db'
    if not db_path.exists():
        raise RuntimeError(f"Database {db_path} does not exist. Run 'micropki db init' first.")

    serial_int = generate_serial(db_path)
    serial_hex = serial_to_hex(serial_int)
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(inter_key.public_key())
    builder = builder.serial_number(serial_int)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=args.pathlen), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski.value)
    builder = builder.add_extension(aki, critical=False)

    hash_algo = hashes.SHA256() if args.key_type == 'rsa' else hashes.SHA384()
    inter_cert = builder.sign(private_key=root_key, algorithm=hash_algo)

    inter_cert_path = certs_dir / 'intermediate.cert.pem'
    inter_cert_pem = inter_cert.public_bytes(serialization.Encoding.PEM)
    inter_cert_path.write_bytes(inter_cert_pem)
    logger.info(f"Intermediate CA certificate saved to {inter_cert_path}")

    cert_data = {
        'serial_hex': serial_hex,
        'subject': subject.rfc4514_string(),
        'issuer': root_cert.subject.rfc4514_string(),
        'not_before': inter_cert.not_valid_before_utc.isoformat(),
        'not_after': inter_cert.not_valid_after_utc.isoformat(),'cert_pem': inter_cert_pem.decode('utf-8'),
        'status': 'valid',
        'created_at': now.isoformat()
    }
    insert_certificate(db_path, cert_data)

    policy_path = out_dir / 'policy.txt'
    with open(policy_path, 'a') as f:
        f.write(f"""
Intermediate CA Information
===================================
Subject DN: {subject.rfc4514_string()}
Serial Number (hex): {serial_hex}
Validity Period:
  Not Before: {inter_cert.not_valid_before_utc.isoformat()}
  Not After : {inter_cert.not_valid_after_utc.isoformat()}Key Algorithm: {args.key_type.upper()}-{args.key_size}
Path Length Constraint: {args.pathlen}
Issuer (Root CA): {root_cert.subject.rfc4514_string()}
Creation Date: {now.isoformat()}
""")

    logger.info("Intermediate CA creation successful")


def issue_certificate(args):
    """Issue an end-entity certificate with policy enforcement."""
    import os
    from datetime import datetime, timedelta, timezone
    from pathlib import Path
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtensionOID

    from .audit import init_audit_log, log_audit
    from .transparency import init_ct_log, log_certificate_to_ct
    from .policy import validate_key_size, validate_validity_days, validate_san_types
    from .compromise import is_key_compromised
    from .serial import generate_serial, serial_to_hex
    from . import crypto_utils
    from . import certificates
    from . import csr as csr_module
    from . import templates
    from .database import insert_certificate

    logger = logging.getLogger(__name__)

    out_dir = Path(args.out_dir)

    # Initialise audit and CT logs
    init_audit_log(out_dir.parent)
    ct_path = init_ct_log(out_dir.parent)

    # Database path
    db_path = Path(args.db_path) if hasattr(args, 'db_path') and args.db_path else out_dir.parent / 'micropki.db'
    if not db_path.exists():
        raise RuntimeError(f"Database {db_path} does not exist. Run 'micropki db init' first.")

    # Load CA
    ca_cert = x509.load_pem_x509_certificate(Path(args.ca_cert).read_bytes())
    ca_pass = crypto_utils.load_passphrase(Path(args.ca_pass_file))
    ca_key = crypto_utils.load_encrypted_private_key(Path(args.ca_key), ca_pass)

    cert_type = 'end_entity'
    template_name = args.template

    # Generate serial number BEFORE using it
    serial_int = generate_serial(db_path)
    serial_hex = serial_to_hex(serial_int)
    now = datetime.now(timezone.utc)

    # Determine subject, san, and public key from either CSR or arguments
    if hasattr(args, 'csr') and args.csr:
        csr_path = Path(args.csr)
        if not csr_path.exists():
            raise FileNotFoundError(f"CSR not found: {csr_path}")
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())

        # Check if public key is compromised
        if is_key_compromised(db_path, csr):
            log_audit("AUDIT", "issue_certificate", "failure",
                      "Certificate request rejected - compromised key",
                      {"subject": str(csr.subject)})
            raise ValueError("This key has been compromised and cannot be used for new certificates")

        # Validate key size from CSR
        public_key = csr.public_key()
        if hasattr(public_key, 'key_size'):
            key_size = public_key.key_size
            key_type = 'rsa'
            valid, msg = validate_key_size(key_size, cert_type, key_type)
            if not valid:
                log_audit("AUDIT", "issue_certificate", "failure", msg, {"subject": str(csr.subject)})
                raise ValueError(msg)

        subject = csr.subject
        san_entries = []
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_entries = list(san_ext.value)
        except x509.ExtensionNotFound:
            pass
        key_path = None
    else:
        # Validate key size for internal generation
        key_type = 'rsa'
        key_size = 2048
        valid, msg = validate_key_size(key_size, cert_type, key_type)
        if not valid:
            log_audit("AUDIT", "issue_certificate", "failure", msg, {"subject": args.subject})
            raise ValueError(msg)

        # Generate new key pair
        ee_key = crypto_utils.generate_rsa_key(2048)
        public_key = ee_key.public_key()
        subject = certificates.parse_dn(args.subject)
        san_entries = []
        if args.san:
            for san_string in args.san:
                san_entries.append(csr_module.parse_san_string(san_string))

        out_dir.mkdir(parents=True, exist_ok=True)
        cn = _get_common_name(subject)
        if not cn:
            cn = f"cert-{serial_hex}"
        key_path = out_dir / f"{cn}.key.pem"
        key_pem = ee_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        crypto_utils.save_pem(key_pem, key_path, mode=0o600)
        logger.warning(f"Private key saved UNENCRYPTED to {key_path}")

    # Validate SAN types against template
    valid, msg = validate_san_types(san_entries, template_name)
    if not valid:
        log_audit("AUDIT", "issue_certificate", "failure", msg, {"subject": str(subject)})
        raise ValueError(msg)

    # Validate server certificate requires SAN
    if template_name == 'server' and not san_entries:
        log_audit("AUDIT", "issue_certificate", "failure",
                  "Server certificate requires at least one SAN",
                  {"subject": str(subject)})
        raise ValueError("Server certificate requires at least one SAN (DNS or IP)")

    # Validate validity period
    valid, msg = validate_validity_days(args.validity_days, cert_type)
    if not valid:
        log_audit("AUDIT", "issue_certificate", "failure", msg, {"subject": str(subject)})
        raise ValueError(msg)

    # Build certificate
    template = templates.get_template(template_name)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_int)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

    builder = builder.add_extension(template.get_basic_constraints(), critical=True)
    builder = builder.add_extension(template.get_key_usage('rsa'), critical=True)
    builder = builder.add_extension(template.get_extended_key_usage(), critical=False)

    if san_entries:
        san_ext = x509.SubjectAlternativeName(san_entries)
        builder = builder.add_extension(san_ext, critical=False)

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)

    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    ee_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Save certificate
    cn = _get_common_name(subject)
    if not cn:
        cn = f"cert-{serial_hex}"
    cert_path = out_dir / f"{cn}.cert.pem"
    cert_pem = ee_cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)
    logger.info(f"Certificate saved to {cert_path}")

    # Insert into database
    cert_data = {
        'serial_hex': serial_hex,
        'subject': subject.rfc4514_string(),
        'issuer': ca_cert.subject.rfc4514_string(),
        'not_before': ee_cert.not_valid_before_utc.isoformat(),
        'not_after': ee_cert.not_valid_after_utc.isoformat(),
        'cert_pem': cert_pem.decode('utf-8'),
        'status': 'valid',
        'created_at': now.isoformat()
    }
    insert_certificate(db_path, cert_data)

    # Audit log
    log_audit("AUDIT", "issue_certificate", "success",
              f"Issued {template_name} certificate for {subject.rfc4514_string()}",
              {"serial": serial_hex, "subject": subject.rfc4514_string(),
               "template": template_name, "sans": [str(s) for s in san_entries]})

    # CT log
    log_certificate_to_ct(ct_path, ee_cert, ca_cert.subject.rfc4514_string())

    logger.info(f"Issued {template_name} certificate:")
    logger.info(f"  Subject: {subject.rfc4514_string()}")
    logger.info(f"  Serial: {serial_hex}")
    if san_entries:
        logger.info(f"  SANs: {san_entries}")

    return ee_cert, None if (hasattr(args, 'csr') and args.csr) else ee_key


def revoke_certificate_cmd(args):
    """Execute certificate revocation command with audit."""
    from .audit import init_audit_log, log_audit
    from .revocation import validate_reason
    from .database import get_certificate_by_serial, update_certificate_status

    logger = logging.getLogger(__name__)

    # Normalize serial number: remove leading zeros
    serial_normalized = args.serial.lstrip('0')
    if not serial_normalized:
        serial_normalized = '0'

    # Define db_path and out_dir BEFORE using
    db_path = Path(args.db_path) if args.db_path else Path('./pki/micropki.db')
    out_dir = db_path.parent

    # Initialise audit log
    init_audit_log(out_dir)

    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    cert_data = get_certificate_by_serial(db_path, serial_normalized)
    if not cert_data:
        log_audit("AUDIT", "revoke_certificate", "failure",
                  f"Certificate {args.serial} not found",
                  {"serial": args.serial})
        raise ValueError(f"Certificate with serial {args.serial} not found")

    if cert_data['status'] == 'revoked':
        logger.warning(f"Certificate {serial_normalized} is already revoked")
        log_audit("AUDIT", "revoke_certificate", "warning",
                  f"Attempted to revoke already revoked certificate {serial_normalized}",
                  {"serial": serial_normalized})
        return False

    # Validate reason
    validate_reason(args.reason)

    # Update database
    update_certificate_status(db_path, serial_normalized, 'revoked', args.reason)
    logger.info(f"Revoked certificate {serial_normalized} with reason: {args.reason}")

    # Audit log
    log_audit("AUDIT", "revoke_certificate", "success",
              f"Revoked certificate {serial_normalized} with reason {args.reason}",
              {"serial": serial_normalized, "reason": args.reason, "subject": cert_data['subject']})

    return True
def revoke_certificate_cmd(args):
    """Execute certificate revocation command with audit."""
    from .audit import init_audit_log, log_audit

    # Нормализация серийного номера: удаляем ведущие нули
    serial_normalized = args.serial.lstrip('0')

    db_path = Path(args.db_path) if args.db_path else Path('./pki/micropki.db')
    out_dir = db_path.parent

    init_audit_log(out_dir)

    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    cert_data = get_certificate_by_serial(db_path, serial_normalized)
    if not cert_data:
        log_audit("AUDIT", "revoke_certificate", "failure",
                  f"Certificate {args.serial} not found",
                  {"serial": args.serial})
        raise ValueError(f"Certificate with serial {args.serial} not found")

    if cert_data['status'] == 'revoked':
        logger.warning(f"Certificate {serial_normalized} is already revoked")
        log_audit("AUDIT", "revoke_certificate", "warning",
                  f"Attempted to revoke already revoked certificate {serial_normalized}",
                  {"serial": serial_normalized})
        return False

    reason_enum = validate_reason(args.reason)
    update_certificate_status(db_path, serial_normalized, 'revoked', args.reason)
    logger.info(f"Revoked certificate {serial_normalized} with reason: {args.reason}")

    log_audit("AUDIT", "revoke_certificate", "success",
              f"Revoked certificate {serial_normalized} with reason {args.reason}",
              {"serial": serial_normalized, "reason": args.reason, "subject": cert_data['subject']})

    return True

def compromise_certificate_cmd(args):
    """Execute certificate compromise command."""
    from .audit import init_audit_log, log_audit
    from .compromise import mark_key_compromised

    cert_path = Path(args.cert)
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate not found: {cert_path}")

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    serial_hex = format(cert.serial_number, 'X')

    out_dir = cert_path.parent.parent
    db_path = out_dir / 'micropki.db'

    init_audit_log(out_dir)

    # Revoke the certificate
    revoke_certificate(db_path, serial_hex, args.reason, args.force)

    # Mark key as compromised
    mark_key_compromised(db_path, serial_hex, args.reason)

    log_audit("AUDIT", "ca_compromise", "success",
              f"Certificate {serial_hex} marked as compromised and revoked",
              {"serial": serial_hex, "cert_path": str(cert_path), "reason": args.reason})

    # Trigger emergency CRL update
    from .crl import generate_crl
    crl_dir = out_dir / 'crl'
    crl_dir.mkdir(parents=True, exist_ok=True)

    # Find CA that issued this certificate
    issuer_dn = cert.issuer.rfc4514_string()
    if "Root" in issuer_dn:
        ca_type = 'root'
        ca_cert_path = out_dir / 'certs' / 'ca.cert.pem'
        ca_key_path = out_dir / 'private' / 'ca.key.pem'
        passphrase_file = out_dir.parent / 'secrets' / 'root.pass'
        output_path = crl_dir / 'root.crl.pem'
    else:
        ca_type = 'intermediate'
        ca_cert_path = out_dir / 'certs' / 'intermediate.cert.pem'
        ca_key_path = out_dir / 'private' / 'intermediate.key.pem'
        passphrase_file = out_dir.parent / 'secrets' / 'intermediate.pass'
        output_path = crl_dir / 'intermediate.crl.pem'

    if ca_cert_path.exists() and ca_key_path.exists() and passphrase_file.exists():
        passphrase = crypto_utils.load_passphrase(passphrase_file)
        generate_crl(
            db_path=db_path,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            ca_passphrase=passphrase,
            next_update_days=7,
            output_path=output_path,
            ca_subject=issuer_dn
        )
        logger.info(f"Emergency CRL generated at {output_path}")

    print(f"Certificate {serial_hex} has been compromised, revoked, and added to blocklist")
def generate_crl_cmd(args):
    """Execute CRL generation command."""
    from .crl import generate_crl
    from .crypto_utils import load_passphrase
    out_dir = Path(args.out_dir) if hasattr(args, 'out_dir') else Path('./pki')
    db_path = Path(args.db_path) if args.db_path else out_dir / 'micropki.db'
    crl_dir = out_dir / 'crl'
    crl_dir.mkdir(parents=True, exist_ok=True)

    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    if args.ca == 'root':
        ca_cert_path = out_dir / 'certs' / 'ca.cert.pem'
        ca_key_path = out_dir / 'private' / 'ca.key.pem'
        ca_subject = "CN=Root CA"
        output_path = args.out_file if args.out_file else crl_dir / 'root.crl.pem'
        passphrase_file = args.passphrase_file if hasattr(args, 'passphrase_file') else None
    elif args.ca == 'intermediate':
        ca_cert_path = out_dir / 'certs' / 'intermediate.cert.pem'
        ca_key_path = out_dir / 'private' / 'intermediate.key.pem'
        ca_subject = "CN=Intermediate CA"
        output_path = args.out_file if args.out_file else crl_dir / 'intermediate.crl.pem'
        passphrase_file = args.passphrase_file if hasattr(args, 'passphrase_file') else None
    else:
        raise ValueError(f"Invalid CA type: {args.ca}. Use 'root' or 'intermediate'")

    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    if not ca_key_path.exists():
        raise FileNotFoundError(f"CA key not found: {ca_key_path}")

    if passphrase_file:
        passphrase = load_passphrase(Path(passphrase_file))
    else:
        default_pass = out_dir.parent / 'secrets' / f'{args.ca}.pass'
        if default_pass.exists():
            passphrase = load_passphrase(default_pass)
        else:
            raise ValueError(f"Passphrase file not provided and default not found: {default_pass}")

    crl = generate_crl(
        db_path=db_path,
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        ca_passphrase=passphrase,
        next_update_days=args.next_update,
        output_path=output_path,
        ca_subject=ca_subject
    )

    logger.info(f"CRL generated successfully: {output_path}")


def issue_ocsp_cert(args):
    """Issue an OCSP signing certificate."""
    from .crypto_utils import generate_rsa_key, generate_ecc_key, save_pem, load_passphrase, load_encrypted_private_key
    from .certificates import parse_dn
    from .csr import parse_san_string
    from .database import insert_certificate
    from .serial import generate_serial, serial_to_hex
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from datetime import datetime, timedelta, timezone
    from pathlib import Path

    logger = logging.getLogger(__name__)

    # Load CA
    ca_cert = x509.load_pem_x509_certificate(Path(args.ca_cert).read_bytes())
    ca_pass = load_passphrase(Path(args.ca_pass_file))
    ca_key = load_encrypted_private_key(Path(args.ca_key), ca_pass)

    # Generate key pair
    if args.key_type == 'rsa':
        key = generate_rsa_key(args.key_size)
    else:
        key = generate_ecc_key()

    # Save unencrypted private key (warning)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / 'ocsp.key.pem'
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    save_pem(key_pem, key_path, mode=0o600)
    logger.warning(f"OCSP responder private key saved UNENCRYPTED to {key_path}")

    # Parse subject and SANs
    subject = parse_dn(args.subject)
    san_entries = []
    if args.san:
        for san in args.san:
            san_entries.append(parse_san_string(san))

    # Database
    db_path = Path(args.db_path) if args.db_path else out_dir.parent / 'micropki.db'
    if not db_path.exists():
        raise RuntimeError(f"Database {db_path} does not exist. Run 'micropki db init' first.")

    serial_int = generate_serial(db_path)
    serial_hex = serial_to_hex(serial_int)
    now = datetime.now(timezone.utc)

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial_int)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

    # Basic Constraints: CA=FALSE (critical)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    # Key Usage: digitalSignature (critical)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    # Extended Key Usage: OCSPSigning
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
        critical=False
    )

    # Subject Alternative Name
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    # SKI/AKI
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    builder = builder.add_extension(ski, critical=False)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    # Sign
    hash_algo = hashes.SHA256() if args.key_type == 'rsa' else hashes.SHA384()
    cert = builder.sign(private_key=ca_key, algorithm=hash_algo)

    # Save certificate
    cert_path = out_dir / 'ocsp.cert.pem'
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)
    logger.info(f"OCSP responder certificate saved to {cert_path}")

    # Insert into database
    cert_data = {
        'serial_hex': serial_hex,
        'subject': subject.rfc4514_string(),
        'issuer': ca_cert.subject.rfc4514_string(),
        'not_before': cert.not_valid_before_utc.isoformat(),
        'not_after': cert.not_valid_after_utc.isoformat(),'cert_pem': cert_pem.decode('utf-8'),
        'status': 'valid',
        'created_at': now.isoformat()
    }
    insert_certificate(db_path, cert_data)

    logger.info(f"Issued OCSP responder certificate with serial {serial_hex}")