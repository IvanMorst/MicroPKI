import logging
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone  # Added timezone

from cryptography.hazmat.primitives import serialization, hashes  # Added hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

from . import crypto_utils
from . import certificates
from . import csr as csr_module
from . import templates
from . import chain


def _write_policy_file(path: Path, cert: x509.Certificate, args):
    """Generate the policy.txt document."""
    content = f"""Certificate Policy for MicroPKI Root CA
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
    path.write_text(content)

def init_ca(args):
    """Execute the 'ca init' command (Sprint 1)."""
    logger = logging.getLogger(__name__)

    # Resolve paths
    out_dir = Path(args.out_dir).resolve()
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    policy_file = out_dir / 'policy.txt'

    # Create directories with proper permissions
    try:
        private_dir.mkdir(parents=True, exist_ok=True)
        certs_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directories in {out_dir}")
    except PermissionError as e:
        raise PermissionError(f"Cannot create directories in {out_dir}: {e}")
    except FileExistsError as e:
        raise FileExistsError(f"Cannot create directory, path exists as file: {out_dir}")
    except Exception as e:
        raise RuntimeError(f"Failed to create directories: {e}")

    try:
        os.chmod(private_dir, 0o700)
    except Exception as e:
        logger.warning(f"Could not set permissions 0700 on {private_dir}: {e}")

    # Load passphrase
    passphrase_file = Path(args.passphrase_file).resolve()
    if not passphrase_file.is_file():
        raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")

    try:
        passphrase = crypto_utils.load_passphrase(passphrase_file)
    except Exception as e:
        raise ValueError(f"Failed to read passphrase file: {e}")

    logger.info("Passphrase loaded (length %d)", len(passphrase))

    # Generate key
    logger.info("Generating %s key...", args.key_type.upper())
    try:
        if args.key_type == 'rsa':
            private_key = crypto_utils.generate_rsa_key(args.key_size)
        else:
            private_key = crypto_utils.generate_ecc_key()
    except Exception as e:
        raise RuntimeError(f"Key generation failed: {e}")

    logger.info("Key generation completed")

    # Encrypt and save private key
    try:
        key_pem = crypto_utils.encrypt_private_key(private_key, passphrase)
        key_path = private_dir / 'ca.key.pem'
        crypto_utils.save_pem(key_pem, key_path, mode=0o600)
        logger.info(f"Encrypted private key saved to {key_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to save encrypted key: {e}")

    # Parse subject DN
    try:
        subject = certificates.parse_dn(args.subject)
    except Exception as e:
        raise ValueError(f"Invalid subject DN: {e}")

    # Generate self-signed certificate
    logger.info("Creating self-signed certificate...")
    try:
        cert = certificates.create_self_signed_cert(
            private_key, subject, args.validity_days, args.key_type
        )
    except Exception as e:
        raise RuntimeError(f"Certificate generation failed: {e}")

    logger.info("Certificate signing completed")

    # Save certificate
    try:
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_path = certs_dir / 'ca.cert.pem'
        cert_path.write_bytes(cert_pem)
        logger.info(f"Certificate saved to {cert_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to save certificate: {e}")

    # Write policy.txt
    try:
        _write_policy_file(policy_file, cert, args)
        logger.info(f"Policy document saved to {policy_file}")
    except Exception as e:
        logger.warning(f"Failed to write policy file: {e}")

    logger.info("Root CA initialisation successful")


def issue_intermediate(args):
    """Execute the 'ca issue-intermediate' command."""
    logger = logging.getLogger(__name__)

    # Resolve paths
    out_dir = Path(args.out_dir).resolve()
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    csrs_dir = out_dir / 'csrs'

    # Create directories
    private_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    csrs_dir.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(private_dir, 0o700)
    except Exception:
        logger.warning(f"Could not set permissions on {private_dir}")

    # Load Root CA materials
    root_cert_path = Path(args.root_cert)
    root_key_path = Path(args.root_key)
    root_pass_file = Path(args.root_pass_file)

    if not root_cert_path.exists():
        raise FileNotFoundError(f"Root certificate not found: {root_cert_path}")
    if not root_key_path.exists():
        raise FileNotFoundError(f"Root key not found: {root_key_path}")
    if not root_pass_file.exists():
        raise FileNotFoundError(f"Root passphrase file not found: {root_pass_file}")

    root_cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
    root_pass = crypto_utils.load_passphrase(root_pass_file)
    root_key = crypto_utils.load_encrypted_private_key(root_key_path, root_pass)

    # Generate Intermediate CA key
    logger.info(f"Generating Intermediate CA {args.key_type.upper()} key...")
    if args.key_type == 'rsa':
        inter_key = crypto_utils.generate_rsa_key(args.key_size)
    else:
        inter_key = crypto_utils.generate_ecc_key()

    # Encrypt and save Intermediate CA key
    inter_pass = crypto_utils.load_passphrase(Path(args.passphrase_file))
    inter_key_pem = crypto_utils.encrypt_private_key(inter_key, inter_pass)
    inter_key_path = private_dir / 'intermediate.key.pem'
    crypto_utils.save_pem(inter_key_pem, inter_key_path, mode=0o600)
    logger.info(f"Intermediate CA key saved to {inter_key_path}")

    # Parse subject
    try:
        subject = certificates.parse_dn(args.subject)
    except Exception as e:
        raise ValueError(f"Invalid subject DN: {e}")

    # Generate CSR
    logger.info("Generating Intermediate CA CSR...")
    inter_csr = csr_module.generate_csr(
        inter_key,
        subject,
        is_ca=True,
        pathlen=args.pathlen
    )
    csr_path = csrs_dir / 'intermediate.csr.pem'
    csr_module.save_csr(inter_csr, csr_path)
    logger.info(f"CSR saved to {csr_path}")

    # Sign CSR with Root CA
    logger.info("Signing Intermediate CA certificate with Root CA...")
    serial = int.from_bytes(os.urandom(20), byteorder='big')
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(inter_csr.subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(inter_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

    # Add extensions
    # BasicConstraints: CA=True with pathlen
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=args.pathlen),
        critical=True
    )

    # KeyUsage: keyCertSign and cRLSign
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
        ),
        critical=True
    )

    # SKI from Intermediate public key
    ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    # AKI from Root CA SKI
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski.value)
    builder = builder.add_extension(aki, critical=False)

    # Sign with Root CA
    if args.key_type == 'rsa':
        hash_algo = hashes.SHA256()
    else:
        hash_algo = hashes.SHA384()

    inter_cert = builder.sign(private_key=root_key, algorithm=hash_algo)

    # Save Intermediate certificate
    inter_cert_path = certs_dir / 'intermediate.cert.pem'
    inter_cert_pem = inter_cert.public_bytes(serialization.Encoding.PEM)
    inter_cert_path.write_bytes(inter_cert_pem)
    logger.info(f"Intermediate CA certificate saved to {inter_cert_path}")

    # Update policy.txt
    _update_policy_with_intermediate(out_dir / 'policy.txt', inter_cert, args)

    logger.info("Intermediate CA creation successful")


def issue_certificate(args):
    """Execute the 'ca issue-cert' command."""
    logger = logging.getLogger(__name__)

    # Load CA materials
    ca_cert_path = Path(args.ca_cert)
    ca_key_path = Path(args.ca_key)
    ca_pass_file = Path(args.ca_pass_file)

    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    if not ca_key_path.exists():
        raise FileNotFoundError(f"CA key not found: {ca_key_path}")
    if not ca_pass_file.exists():
        raise FileNotFoundError(f"CA passphrase file not found: {ca_pass_file}")

    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_pass = crypto_utils.load_passphrase(ca_pass_file)
    ca_key = crypto_utils.load_encrypted_private_key(ca_key_path, ca_pass)

    # Get template
    template = templates.get_template(args.template)

    # Parse SANs if provided
    san_entries = []
    if args.san:
        for san_string in args.san:
            try:
                san_entry = csr_module.parse_san_string(san_string)
                san_entries.append(san_entry)
            except ValueError as e:
                raise ValueError(f"Invalid SAN '{san_string}': {e}")

    # Validate SAN types against template
    if not template.validate_san_types(san_entries):
        allowed = ', '.join(template.get_allowed_san_types())
        raise ValueError(f"Invalid SAN types for {args.template} template. Allowed: {allowed}")

    # Check required SAN for server template
    if args.template == 'server' and not san_entries:
        raise ValueError("Server certificate requires at least one SAN (DNS or IP)")

    # Generate key pair for end-entity
    logger.info(f"Generating end-entity key pair...")
    key_type = 'rsa'  # Default, could be made configurable
    if key_type == 'rsa':
        ee_key = crypto_utils.generate_rsa_key(2048)  # Minimum 2048 for end-entity
    else:
        ee_key = crypto_utils.generate_ecc_key()  # P-384 for ECC

    # Parse subject
    try:
        subject = certificates.parse_dn(args.subject)
    except Exception as e:
        raise ValueError(f"Invalid subject DN: {e}")

    # Build certificate
    serial = int.from_bytes(os.urandom(20), byteorder='big')
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(ee_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

    # Add template-based extensions
    # BasicConstraints: CA=FALSE
    builder = builder.add_extension(
        template.get_basic_constraints(),
        critical=True
    )

    # KeyUsage
    builder = builder.add_extension(
        template.get_key_usage(key_type),
        critical=True
    )

    # ExtendedKeyUsage
    builder = builder.add_extension(
        template.get_extended_key_usage(),
        critical=False
    )

    # SubjectAlternativeName
    if san_entries:
        san_ext = x509.SubjectAlternativeName(san_entries)
        builder = builder.add_extension(san_ext, critical=False)

    # SKI
    ski = x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    # AKI
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    # Sign with CA key
    hash_algo = hashes.SHA256()  # Standard for end-entity
    ee_cert = builder.sign(private_key=ca_key, algorithm=hash_algo)

    # Determine output filenames
    cn = _get_common_name(subject)
    if not cn:
        cn = f"cert-{format(serial, 'X')}"

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cert_path = out_dir / f"{cn}.cert.pem"
    key_path = out_dir / f"{cn}.key.pem"

    # Save certificate
    cert_pem = ee_cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)
    logger.info(f"Certificate saved to {cert_path}")

    # Save unencrypted private key
    key_pem = ee_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    crypto_utils.save_pem(key_pem, key_path, mode=0o600)
    logger.warning(f"Private key saved UNENCRYPTED to {key_path}")

    # Log issuance
    logger.info(f"Issued {args.template} certificate:")
    logger.info(f"  Subject: {args.subject}")
    logger.info(f"  Serial: {format(serial, 'X')}")
    logger.info(f"  SANs: {args.san if args.san else 'None'}")

    return ee_cert, ee_key


def _get_common_name(name: x509.Name) -> str:
    """Extract CN from DN."""
    cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return cn_attrs[0].value
    return None


def _update_policy_with_intermediate(policy_path: Path, inter_cert: x509.Certificate, args):
    """Append Intermediate CA info to policy.txt."""
    with open(policy_path, 'a') as f:
        f.write(f"""
Intermediate CA Information
===================================
Subject DN: {inter_cert.subject.rfc4514_string()}
Serial Number (hex): {format(inter_cert.serial_number, 'X')}
Validity Period:
  Not Before: {inter_cert.not_valid_before_utc.isoformat()}
  Not After : {inter_cert.not_valid_after_utc.isoformat()}
Key Algorithm: {args.key_type.upper()}-{args.key_size}
Path Length Constraint: {args.pathlen}
Issuer (Root CA): {inter_cert.issuer.rfc4514_string()}
Creation Date: {datetime.now(timezone.utc).isoformat()}
""")