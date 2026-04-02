import pytest
import tempfile
import os
from pathlib import Path
from micropki.database import init_db, insert_certificate, get_certificate_by_serial, list_certificates, \
    update_certificate_status


@pytest.fixture
def db_path():
    """Create a temporary database file for testing."""
    # Use a fixed path in temp directory to avoid Windows issues
    temp_dir = Path(tempfile.gettempdir()) / "micropki_test"
    temp_dir.mkdir(exist_ok=True)
    db_file = temp_dir / "test.db"

    # Remove existing file if any
    if db_file.exists():
        db_file.unlink()

    init_db(db_file)
    yield db_file

    # Cleanup
    if db_file.exists():
        db_file.unlink()


def test_init_db_creates_schema(db_path):
    """Test that database initialisation creates tables"""
    assert db_path.exists()
    # Verify we can insert data
    cert_data = {
        'serial_hex': 'TEST001',
        'subject': 'CN=Test',
        'issuer': 'CN=CA',
        'not_before': '2025-01-01T00:00:00',
        'not_after': '2026-01-01T00:00:00',
        'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
        'status': 'valid',
        'created_at': '2025-01-01T00:00:00'
    }
    insert_certificate(db_path, cert_data)
    retrieved = get_certificate_by_serial(db_path, 'TEST001')
    assert retrieved is not None


def test_insert_and_retrieve(db_path):
    cert_data = {
        'serial_hex': 'ABC123',
        'subject': 'CN=Test Certificate',
        'issuer': 'CN=Test CA',
        'not_before': '2025-01-01T00:00:00',
        'not_after': '2026-01-01T00:00:00',
        'cert_pem': '-----BEGIN CERTIFICATE-----\nTESTCERT\n-----END CERTIFICATE-----',
        'status': 'valid',
        'created_at': '2025-01-01T00:00:00'
    }
    insert_certificate(db_path, cert_data)
    retrieved = get_certificate_by_serial(db_path, 'ABC123')
    assert retrieved is not None
    assert retrieved['serial_hex'] == 'ABC123'
    assert retrieved['subject'] == 'CN=Test Certificate'


def test_insert_duplicate_serial_fails(db_path):
    cert_data = {
        'serial_hex': 'DUPLICATE',
        'subject': 'CN=Test1',
        'issuer': 'CN=CA',
        'not_before': '2025-01-01T00:00:00',
        'not_after': '2026-01-01T00:00:00',
        'cert_pem': 'CERT1',
        'status': 'valid',
        'created_at': '2025-01-01T00:00:00'
    }
    insert_certificate(db_path, cert_data)

    cert_data2 = {
        'serial_hex': 'DUPLICATE',
        'subject': 'CN=Test2',
        'issuer': 'CN=CA',
        'not_before': '2025-01-01T00:00:00',
        'not_after': '2026-01-01T00:00:00',
        'cert_pem': 'CERT2',
        'status': 'valid',
        'created_at': '2025-01-01T00:00:00'
    }
    with pytest.raises(ValueError, match="Duplicate serial number"):
        insert_certificate(db_path, cert_data2)


def test_list_certificates(db_path):
    # Insert multiple certificates
    for i in range(3):
        cert_data = {
            'serial_hex': f'LIST{i:03d}',
            'subject': f'CN=Test{i}',
            'issuer': 'CN=CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': f'CERT{i}',
            'status': 'valid',
            'created_at': '2025-01-01T00:00:00'
        }
        insert_certificate(db_path, cert_data)

    certs = list_certificates(db_path)
    assert len(certs) == 3


def test_list_certificates_filter_by_status(db_path):
    cert_data = {
        'serial_hex': 'VALID001',
        'subject': 'CN=Valid',
        'issuer': 'CN=CA',
        'not_before': '2025-01-01T00:00:00',
        'not_after': '2026-01-01T00:00:00',
        'cert_pem': 'VALID',
        'status': 'valid',
        'created_at': '2025-01-01T00:00:00'
    }
    insert_certificate(db_path, cert_data)

    valid_certs = list_certificates(db_path, status='valid')
    assert len(valid_certs) == 1

    revoked_certs = list_certificates(db_path, status='revoked')
    assert len(revoked_certs) == 0


def test_update_certificate_status(db_path):
    cert_data = {
        'serial_hex': 'UPDATE001',
        'subject': 'CN=Test',
        'issuer': 'CN=CA',
        'not_before': '2025-01-01T00:00:00',
        'not_after': '2026-01-01T00:00:00',
        'cert_pem': 'CERT',
        'status': 'valid',
        'created_at': '2025-01-01T00:00:00'
    }
    insert_certificate(db_path, cert_data)

    update_certificate_status(db_path, 'UPDATE001', 'revoked', 'Compromised')

    cert = get_certificate_by_serial(db_path, 'UPDATE001')
    assert cert['status'] == 'revoked'