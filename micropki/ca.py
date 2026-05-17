import logging
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from . import crypto_utils
from . import certificates
from . import csr as csr_module
from . import templates
from .database import insert_certificate, get_certificate_by_serial, list_certificates
from .serial import generate_serial, serial_to_hex
from .revocation import revoke_certificate, validate_reason
from .crl import generate_crl

logger = logging.getLogger(__name__)


def init_ca(args):
    """Initialize self-signed Root CA (Sprint 1) with optional DB insertion."""
    out_dir = Path(args.out_dir).resolve()
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
            'not_before': cert.not_valid_before.isoformat(),
            'not_after': cert.not_valid_after.isoformat(),
            'cert_pem': cert_pem.decode('utf-8'),
            'status': 'valid',
            'created_at': now.isoformat()
        }
        insert_certificate(db_path, cert_data)

    policy_path = out_dir / 'policy.txt'
    policy_path.write_text(_policy_content(cert, args))
    logger.info(f"Policy document saved to {policy_path}")

    logger.info("Root CA initialisation successful")


def _policy_content(cert, args):
    return f"""Certificate Policy for MicroPKI Root CA
===================================
CA Name (Subject): {cert.subject.rfc4514_string()}
Certificate Serial Number (hex): {format(cert.serial_number, 'X')}
Validity Period:
  Not Before: {cert.not_valid_before.isoformat()}
  Not After : {cert.not_valid_after.isoformat()}
Key Algorithm: {args.key_type.upper()}-{args.key_size}
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: {datetime.now(timezone.utc).isoformat()}
"""


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

    cert_data = {
        'serial_hex': serial_hex,
        'subject': subject.rfc4514_string(),
        'issuer': root_cert.subject.rfc4514_string(),
        'not_before': inter_cert.not_valid_before.isoformat(),
        'not_after': inter_cert.not_valid_after.isoformat(),
        'cert_pem': inter_cert_pem.decode('utf-8'),
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
  Not Before: {inter_cert.not_valid_before.isoformat()}
  Not After : {inter_cert.not_valid_after.isoformat()}
Key Algorithm: {args.key_type.upper()}-{args.key_size}
Path Length Constraint: {args.pathlen}
Issuer (Root CA): {root_cert.subject.rfc4514_string()}
Creation Date: {now.isoformat()}
""")

    logger.info(f"Intermediate CA certificate saved to {inter_cert_path}")


def issue_certificate(args):
    """Issue an end-entity certificate."""
    ca_cert = x509.load_pem_x509_certificate(Path(args.ca_cert).read_bytes())
    ca_pass = crypto_utils.load_passphrase(Path(args.ca_pass_file))
    ca_key = crypto_utils.load_encrypted_private_key(Path(args.ca_key), ca_pass)

    template = templates.get_template(args.template)
    san_entries = []
    if args.san:
        for san_string in args.san:
            san_entries.append(csr_module.parse_san_string(san_string))

    if not template.validate_san_types(san_entries):
        allowed = ', '.join(template.get_allowed_san_types())
        raise ValueError(f"Invalid SAN types for {args.template} template. Allowed: {allowed}")

    if args.template == 'server' and not san_entries:
        raise ValueError("Server certificate requires at least one SAN (DNS or IP)")

    ee_key = crypto_utils.generate_rsa_key(2048)
    subject = certificates.parse_dn(args.subject)

    out_dir = Path(args.out_dir).resolve()
    db_path = Path(args.db_path) if hasattr(args, 'db_path') and args.db_path else out_dir.parent / 'micropki.db'
    if not db_path.exists():
        raise RuntimeError(f"Database {db_path} does not exist. Run 'micropki db init' first.")

    serial_int = generate_serial(db_path)
    serial_hex = serial_to_hex(serial_int)
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(ee_key.public_key())
    builder = builder.serial_number(serial_int)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

    builder = builder.add_extension(template.get_basic_constraints(), critical=True)
    builder = builder.add_extension(template.get_key_usage('rsa'), critical=True)
    builder = builder.add_extension(template.get_extended_key_usage(), critical=False)

    if san_entries:
        san_ext = x509.SubjectAlternativeName(san_entries)
        builder = builder.add_extension(san_ext, critical=False)

    ski = x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    ee_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    out_dir.mkdir(parents=True, exist_ok=True)
    cn = _get_common_name(subject)
    if not cn:
        cn = f"cert-{serial_hex}"
    cert_path = out_dir / f"{cn}.cert.pem"
    key_path = out_dir / f"{cn}.key.pem"

    cert_pem = ee_cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)

    key_pem = ee_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    crypto_utils.save_pem(key_pem, key_path, mode=0o600)

    cert_data = {
        'serial_hex': serial_hex,
        'subject': subject.rfc4514_string(),
        'issuer': ca_cert.subject.rfc4514_string(),
        'not_before': ee_cert.not_valid_before.isoformat(),
        'not_after': ee_cert.not_valid_after.isoformat(),
        'cert_pem': cert_pem.decode('utf-8'),
        'status': 'valid',
        'created_at': now.isoformat()
    }
    insert_certificate(db_path, cert_data)

    logger.info(f"Issued {args.template} certificate:")
    logger.info(f"  Subject: {args.subject}")
    logger.info(f"  Serial: {serial_hex}")
    logger.info(f"  SANs: {args.san if args.san else 'None'}")
    logger.warning(f"Private key saved UNENCRYPTED to {key_path}")


def revoke_certificate_cmd(args):
    """Execute certificate revocation command."""
    db_path = Path(args.db_path) if args.db_path else Path('./pki/micropki.db')
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    success = revoke_certificate(db_path, args.serial, args.reason, args.force)
    if success:
        logger.info(f"Certificate {args.serial} revoked successfully")


def generate_crl_cmd(args):
    """Execute CRL generation command."""
    out_dir = Path(args.out_dir) if hasattr(args, 'out_dir') else Path('./pki')
    db_path = Path(args.db_path) if args.db_path else out_dir / 'micropki.db'
    crl_dir = out_dir / 'crl'
    crl_dir.mkdir(parents=True, exist_ok=True)

    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    # Determine CA type and paths
    if args.ca == 'root':
        ca_cert_path = out_dir / 'certs' / 'ca.cert.pem'
        ca_key_path = out_dir / 'private' / 'ca.key.pem'
        ca_subject = "CN=Root CA"  # Will be read from cert
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

    # Get passphrase
    if passphrase_file:
        passphrase = crypto_utils.load_passphrase(Path(passphrase_file))
    else:
        # Try to find appropriate passphrase file
        default_pass = out_dir.parent / 'secrets' / f'{args.ca}.pass'
        if default_pass.exists():
            passphrase = crypto_utils.load_passphrase(default_pass)
        else:
            raise ValueError(f"Passphrase file not provided and default not found: {default_pass}")

    # Generate CRL
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
    import logging
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
        'not_before': cert.not_valid_before.isoformat(),
        'not_after': cert.not_valid_after.isoformat(),
        'cert_pem': cert_pem.decode('utf-8'),
        'status': 'valid',
        'created_at': now.isoformat()
    }
    insert_certificate(db_path, cert_data)

    logger.info(f"Issued OCSP responder certificate with serial {serial_hex}")
def _get_common_name(name: x509.Name) -> str:
    cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn_attrs[0].value if cn_attrs else None
