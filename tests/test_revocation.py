import pytest
import tempfile
from pathlib import Path
from micropki.database import init_db, insert_certificate, get_certificate_by_serial
from micropki.revocation import revoke_certificate, validate_reason, RevocationReason


@pytest.fixture
def db_path():
    # Используем временную директорию вместо NamedTemporaryFile на Windows
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / 'test.db'
        init_db(path)
        yield path


@pytest.fixture
def sample_cert(db_path):
    cert_data = {
        'serial_hex': 'ABC123',
        'subject': 'CN=Test',
        'issuer': 'CN=TestCA',
        'not_before': '2025-01-01T00:00:00',
        'not_after': '2026-01-01T00:00:00',
        'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
        'status': 'valid',
        'created_at': '2025-01-01T00:00:00'
    }
    insert_certificate(db_path, cert_data)
    return 'ABC123'


def test_revoke_valid_certificate(db_path, sample_cert):
    result = revoke_certificate(db_path, sample_cert, 'keyCompromise', force=True)
    assert result is True

    cert = get_certificate_by_serial(db_path, sample_cert)
    assert cert['status'] == 'revoked'
    assert cert['revocation_reason'] == 'keyCompromise'
    assert cert['revocation_date'] is not None


def test_revoke_already_revoked(db_path, sample_cert):
    revoke_certificate(db_path, sample_cert, 'keyCompromise', force=True)
    result = revoke_certificate(db_path, sample_cert, 'superseded', force=True)
    assert result is False


def test_revoke_nonexistent_certificate(db_path):
    with pytest.raises(ValueError, match="not found"):
        revoke_certificate(db_path, 'XYZ999', 'unspecified', force=True)


def test_validate_reason():
    assert validate_reason('keyCompromise') == RevocationReason.KEY_COMPROMISE
    assert validate_reason('cACompromise') == RevocationReason.CA_COMPROMISE
    assert validate_reason('unspecified') == RevocationReason.UNSPECIFIED

    with pytest.raises(ValueError):
        validate_reason('invalid_reason')