import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from . import crypto_utils
from . import certificates

def init_ca(args):
    """Execute the 'ca init' command."""
    logger = logging.getLogger(__name__)

    # Resolve paths
    out_dir = Path(args.out_dir).resolve()
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    policy_file = out_dir / 'policy.txt'

    # Create directories with proper permissions
    private_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(private_dir, 0o700)
    except Exception:
        logger.warning(f"Could not set permissions 0700 on {private_dir}")

    # Load passphrase
    passphrase_file = Path(args.passphrase_file).resolve()
    if not passphrase_file.is_file():
        raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")
    passphrase = crypto_utils.load_passphrase(passphrase_file)
    logger.info("Passphrase loaded (length %d)", len(passphrase))

    # Generate key
    logger.info("Generating %s key...", args.key_type.upper())
    if args.key_type == 'rsa':
        private_key = crypto_utils.generate_rsa_key(args.key_size)
    else:
        private_key = crypto_utils.generate_ecc_key()
    logger.info("Key generation completed")

    # Encrypt and save private key
    key_pem = crypto_utils.encrypt_private_key(private_key, passphrase)
    key_path = private_dir / 'ca.key.pem'
    crypto_utils.save_pem(key_pem, key_path, mode=0o600)
    logger.info("Encrypted private key saved to %s", key_path)

    # Parse subject DN
    try:
        subject = certificates.parse_dn(args.subject)
    except Exception as e:
        raise ValueError(f"Invalid subject DN: {e}")

    # Generate self-signed certificate
    logger.info("Creating self-signed certificate...")
    cert = certificates.create_self_signed_cert(
        private_key, subject, args.validity_days, args.key_type
    )
    logger.info("Certificate signing completed")

    # Save certificate
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_path = certs_dir / 'ca.cert.pem'
    cert_path.write_bytes(cert_pem)
    logger.info("Certificate saved to %s", cert_path)

    # Write policy.txt
    _write_policy_file(policy_file, cert, args)
    logger.info("Policy document saved to %s", policy_file)

    logger.info("Root CA initialisation successful")

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