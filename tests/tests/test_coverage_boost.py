import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import generate_rsa_key, load_encrypted_private_key
from micropki.database import init_db, get_certificate_by_serial
from micropki.revocation_check import check_ocsp, check_crl
from micropki.ocsp_responder import OCSPHandler


def test_load_encrypted_private_key():
    """Test loading encrypted private key."""
    key = generate_rsa_key(2048)
    passphrase = b"test123"

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
        f.write(key_pem)
        path = Path(f.name)

    loaded = load_encrypted_private_key(path, passphrase)
    assert loaded.key_size == 2048
    path.unlink()


def test_get_certificate_by_serial_normalized():
    """Test certificate retrieval with serial number normalization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        # Insert certificate with serial without leading zero
        cert_data = {
            'serial_hex': 'ABC123',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': datetime.now().isoformat(),
            'not_after': (datetime.now() + timedelta(days=30)).isoformat(),
            'cert_pem': 'DUMMY',
            'status': 'valid',
            'created_at': datetime.now().isoformat()
        }
        from micropki.database import insert_certificate
        insert_certificate(db_path, cert_data)

        # Query with leading zero should still find it
        cert = get_certificate_by_serial(db_path, '0ABC123')
        assert cert is not None
        assert cert['serial_hex'] == 'ABC123'


@patch('requests.post')
def test_check_ocsp_network_error(mock_post):
    """Test OCSP check with network error."""
    mock_post.side_effect = Exception("Network error")

    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .sign(key, hashes.SHA256())

    status, detail = check_ocsp(cert, cert, ocsp_url="http://localhost:8080")
    assert status == 'error'
    assert "Network error" in detail


@patch('requests.get')
def test_check_crl_network_error(mock_get):
    """Test CRL check with network error."""
    mock_get.side_effect = Exception("Network error")

    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .sign(key, hashes.SHA256())

    status, detail = check_crl(cert, cert, crl_url="http://localhost:8080/crl")
    assert status == 'error'
    assert "CRL fetch error" in detail