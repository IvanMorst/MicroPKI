# tests/test_compromise.py
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import generate_rsa_key
from micropki.database import init_db, insert_certificate
from micropki.compromise import mark_key_compromised, is_key_compromised, init_compromised_table


def test_init_compromised_table():
    """Test compromised keys table initialization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)
        init_compromised_table(db_path)

        # Verify table exists by inserting and querying
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='compromised_keys'")
        assert cursor.fetchone() is not None
        conn.close()


def test_mark_key_compromised():
    """Test marking a key as compromised."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)
        init_compromised_table(db_path)

        # Create a certificate
        key = generate_rsa_key(2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(subject) \
            .public_key(key.public_key()) \
            .serial_number(1) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=365)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Insert certificate into database
        cert_data = {
            'serial_hex': '1',
            'subject': subject.rfc4514_string(),
            'issuer': subject.rfc4514_string(),
            'not_before': now.isoformat(),
            'not_after': (now + timedelta(days=365)).isoformat(),
            'cert_pem': cert_pem.decode('utf-8'),
            'status': 'valid',
            'created_at': now.isoformat()
        }
        insert_certificate(db_path, cert_data)

        # Mark as compromised
        result = mark_key_compromised(db_path, '1', 'keyCompromise')
        assert result is True