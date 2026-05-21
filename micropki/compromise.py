import hashlib
import logging
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .database import get_certificate_by_serial
logger = logging.getLogger(__name__)


def init_compromised_table(db_path: Path):
    """Create compromised_keys table if not exists."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS compromised_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key_hash TEXT UNIQUE NOT NULL,
                certificate_serial TEXT NOT NULL,
                compromise_date TEXT NOT NULL,
                compromise_reason TEXT NOT NULL,
                FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
            )
        """)
        conn.commit()
    finally:
        conn.close()


def get_public_key_hash(cert: x509.Certificate) -> str:
    """Compute SHA-256 hash of DER-encoded public key (SPKI)."""
    public_key_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_key_bytes).hexdigest()


def get_public_key_hash_from_key(key) -> str:
    """Compute SHA-256 hash of a private key's public part."""
    public_key_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_key_bytes).hexdigest()


def mark_key_compromised(db_path: Path, cert_serial: str, reason: str) -> bool:
    """Mark a certificate's public key as compromised."""
    init_compromised_table(db_path)

    cert_data = get_certificate_by_serial(db_path, cert_serial)
    if not cert_data:
        return False

    # Need to load actual certificate to get public key
    cert_pem = cert_data['cert_pem']
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    public_key_hash = get_public_key_hash(cert)

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("""
            INSERT OR IGNORE INTO compromised_keys 
            (public_key_hash, certificate_serial, compromise_date, compromise_reason)
            VALUES (?, ?, ?, ?)
        """, (public_key_hash, cert_serial, datetime.now(timezone.utc).isoformat(), reason))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to mark key compromised: {e}")
        return False
    finally:
        conn.close()


def is_key_compromised(db_path: Path, csr) -> bool:
    """Check if a CSR's public key is in compromised keys table."""
    init_compromised_table(db_path)

    public_key_bytes = csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()

    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute("SELECT 1 FROM compromised_keys WHERE public_key_hash = ?", (public_key_hash,))
        return cursor.fetchone() is not None
    finally:
        conn.close()