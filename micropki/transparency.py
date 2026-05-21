import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


def init_ct_log(out_dir: Path) -> Path:
    """Initialise Certificate Transparency log file."""
    audit_dir = out_dir / 'audit'
    audit_dir.mkdir(parents=True, exist_ok=True)
    ct_path = audit_dir / 'ct.log'
    return ct_path


def log_certificate_to_ct(ct_path: Path, cert: x509.Certificate, issuer_dn: str):
    """Append certificate entry to CT log."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec='microseconds')
    serial_hex = format(cert.serial_number, 'X')
    subject_dn = cert.subject.rfc4514_string()

    # Calculate SHA-256 fingerprint
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    log_entry = f"{timestamp} | {serial_hex} | {subject_dn} | {fingerprint} | {issuer_dn}\n"

    with open(ct_path, 'a', encoding='utf-8') as f:
        f.write(log_entry)
        f.flush()

    logger.info(f"CT log entry added for certificate {serial_hex}")


def verify_certificate_in_ct(ct_path: Path, serial_hex: str) -> bool:
    """Check if certificate appears in CT log."""
    if not ct_path.exists():
        return False

    with open(ct_path, 'r', encoding='utf-8') as f:
        for line in f:
            if serial_hex in line:
                return True
    return False