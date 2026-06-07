import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import ExtensionOID

from .database import list_certificates, get_certificate_by_serial
from .revocation import RevocationReason

logger = logging.getLogger(__name__)


def get_crl_number(db_path: Path, ca_subject: str) -> int:
    """Get current CRL number from metadata table."""
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute(
            "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,)
        )
        row = cursor.fetchone()
        if row:
            return row[0] + 1
        return 1
    finally:
        conn.close()


def update_crl_metadata(db_path: Path, ca_subject: str, crl_number: int,
                        next_update: datetime, crl_path: Path):
    """Update CRL metadata in database."""
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("""
            INSERT OR REPLACE INTO crl_metadata 
            (ca_subject, crl_number, last_generated, next_update, crl_path)
            VALUES (?, ?, ?, ?, ?)
        """, (
            ca_subject, crl_number, datetime.now(timezone.utc).isoformat(),
            next_update.isoformat(), str(crl_path)
        ))
        conn.commit()
    finally:
        conn.close()


def get_revoked_certificates(db_path: Path, issuer_dn: str) -> List[Dict[str, Any]]:
    """Get all revoked certificates issued by a specific CA."""
    certs = list_certificates(db_path, status='revoked')
    return [c for c in certs if c['issuer'] == issuer_dn]


def generate_crl(
        db_path: Path,
        ca_cert_path: Path,
        ca_key_path: Path,
        ca_passphrase: bytes,
        next_update_days: int,
        output_path: Path,
        ca_subject: str
) -> x509.CertificateRevocationList:
    """Generate a CRL for a CA."""
    from .crypto_utils import load_encrypted_private_key

    # Convert output_path to Path if it's a string
    if isinstance(output_path, str):
        output_path = Path(output_path)

    # Load CA certificate and key
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

    # Get revoked certificates
    revoked_certs = get_revoked_certificates(db_path, ca_cert.subject.rfc4514_string())

    # Build CRL
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=next_update_days)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(next_update)

    # Add revoked certificates
    for cert in revoked_certs:
        revoked_cert = get_certificate_by_serial(db_path, cert['serial_hex'])
        if revoked_cert:
            rev_date = datetime.fromisoformat(revoked_cert['revocation_date'])
            rev_builder = x509.RevokedCertificateBuilder()
            rev_builder = rev_builder.serial_number(int(cert['serial_hex'], 16))
            rev_builder = rev_builder.revocation_date(rev_date)

            # Add reason code if available
            if revoked_cert.get('revocation_reason'):
                reason_str = revoked_cert['revocation_reason'].upper().replace('-', '_')
                try:
                    reason_enum = RevocationReason[reason_str]
                    rev_builder = rev_builder.add_extension(
                        x509.CRLReason(reason_enum.value),
                        critical=False
                    )
                except KeyError:
                    pass

            builder = builder.add_revoked_certificate(rev_builder.build())

    # Add CRL extensions
    # Authority Key Identifier - extract from CA certificate
    try:
        aki_ext = ca_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        builder = builder.add_extension(aki_ext.value, critical=False)
    except x509.ExtensionNotFound:
        # Create AKI from subject key identifier if not present
        ski_ext = ca_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value)
        builder = builder.add_extension(aki, critical=False)

    # CRL Number
    crl_number = get_crl_number(db_path, ca_subject)
    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    # Determine hash algorithm from CA certificate
    sig_alg = ca_cert.signature_algorithm_oid._name
    if 'sha256' in sig_alg or 'rsa' in sig_alg:
        hash_algo = hashes.SHA256()
    elif 'sha384' in sig_alg:
        hash_algo = hashes.SHA384()
    else:
        hash_algo = hashes.SHA256()

    crl = builder.sign(private_key=ca_key, algorithm=hash_algo)

    # Save CRL
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)
    output_path.write_bytes(crl_pem)
    try:
        os.chmod(output_path, 0o644)
    except Exception:
        pass

    # Update metadata
    update_crl_metadata(db_path, ca_subject, crl_number, next_update, output_path)

    logger.info(f"Generated CRL for {ca_subject}")
    logger.info(f"  Number: {crl_number}")
    logger.info(f"  Revoked certificates: {len(revoked_certs)}")
    logger.info(f"  Next update: {next_update.isoformat()}")
    logger.info(f"  Saved to: {output_path}")

    return crl
