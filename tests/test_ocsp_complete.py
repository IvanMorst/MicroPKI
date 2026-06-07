import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.ocsp import build_ocsp_response, compute_issuer_hashes
from micropki.crypto_utils import generate_rsa_key
from micropki.database import init_db, insert_certificate, update_certificate_status, get_db_connection


@pytest.fixture
def ocsp_test_env():
    """Fixture that provides a complete test environment"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        # Create CA
        ca_key = generate_rsa_key(2048)
        ca_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.now(timezone.utc)
        ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())

        ca_cert = x509.CertificateBuilder() \
            .subject_name(ca_subj) \
            .issuer_name(ca_subj) \
            .public_key(ca_key.public_key()) \
            .serial_number(1) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=365)) \
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
            .add_extension(ski, critical=False) \
            .add_extension(aki, critical=False) \
            .sign(ca_key, hashes.SHA256())

        # Create OCSP responder cert
        ocsp_key = generate_rsa_key(2048)
        ocsp_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")])
        ocsp_cert = x509.CertificateBuilder() \
            .subject_name(ocsp_subj) \
            .issuer_name(ca_subj) \
            .public_key(ocsp_key.public_key()) \
            .serial_number(2) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=365)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(ca_key, hashes.SHA256())

        # Create test certificates
        test_certs = []
        for serial, name in [(100, "Valid Cert"), (200, "Revoked Cert")]:
            key = generate_rsa_key(2048)
            subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            cert = x509.CertificateBuilder() \
                .subject_name(subj) \
                .issuer_name(ca_subj) \
                .public_key(key.public_key()) \
                .serial_number(serial) \
                .not_valid_before(now) \
                .not_valid_after(now + timedelta(days=30)) \
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
                .sign(ca_key, hashes.SHA256())
            test_certs.append((serial, cert))

            cert_data = {
                'serial_hex': format(serial, 'X'),
                'subject': subj.rfc4514_string(),
                'issuer': ca_subj.rfc4514_string(),
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat(),
                'cert_pem': cert.public_bytes(serialization.Encoding.PEM).decode(),
                'status': 'valid',
                'created_at': now.isoformat()
            }
            insert_certificate(db_path, cert_data)

        yield {
            'db_path': db_path,
            'ca_cert': ca_cert,
            'ocsp_key': ocsp_key,
            'ocsp_cert': ocsp_cert,
            'test_certs': test_certs
        }


def create_der_request_with_serial(serial_number: int) -> bytes:
    """Create a simple DER-encoded OCSP request with given serial number"""
    serial_hex = format(serial_number, 'x')
    if len(serial_hex) % 2:
        serial_hex = '0' + serial_hex
    serial_bytes = bytes.fromhex(serial_hex)

    der = b'\x30'  # SEQUENCE tag
    der += bytes([len(serial_bytes) + 2])  # length
    der += b'\x02'  # INTEGER tag
    der += bytes([len(serial_bytes)])  # length
    der += serial_bytes

    return der


def test_ocsp_compute_issuer_hashes(ocsp_test_env):
    """Test compute_issuer_hashes coverage"""
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

    name_hash, key_hash = compute_issuer_hashes(cert)
    assert len(name_hash) == 20
    assert len(key_hash) == 20


def test_ocsp_response_for_valid_certificate(ocsp_test_env):
    """Test OCSP response for valid certificate"""
    der_data = create_der_request_with_serial(100)

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )
    assert response is not None
    assert len(response) > 0


def test_ocsp_response_for_revoked_certificate(ocsp_test_env):
    """Test OCSP response for revoked certificate"""
    # Revoke the certificate
    update_certificate_status(ocsp_test_env['db_path'], 'C8', 'revoked', 'keyCompromise')

    der_data = create_der_request_with_serial(200)

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )
    assert response is not None
    assert len(response) > 0


def test_ocsp_response_for_revoked_certificate_no_reason(ocsp_test_env):
    """Test OCSP response for revoked certificate without reason"""
    # Update certificate without revocation reason
    conn = get_db_connection(ocsp_test_env['db_path'])
    try:
        conn.execute(
            "UPDATE certificates SET status = ?, revocation_reason = ?, revocation_date = ? WHERE serial_hex = ?",
            ('revoked', None, datetime.now(timezone.utc).isoformat(), 'C8')
        )
        conn.commit()
    finally:
        conn.close()

    der_data = create_der_request_with_serial(200)

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )
    assert response is not None
    assert len(response) > 0


def test_ocsp_response_for_unknown_certificate(ocsp_test_env):
    """Test OCSP response for unknown certificate (not in DB)"""
    der_data = create_der_request_with_serial(999)

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )
    assert response is not None
    assert len(response) > 0


def test_ocsp_response_with_empty_request(ocsp_test_env):
    """Test OCSP response with empty request data"""
    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=b'',
        cache_ttl=60
    )
    assert response is not None


def test_ocsp_response_with_malformed_request(ocsp_test_env):
    """Test OCSP response with malformed request data"""
    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=b'\x00\x01\x02\xff\xfe\xfd',
        cache_ttl=60
    )
    assert response is not None


def test_ocsp_response_with_cache(ocsp_test_env):
    """Test OCSP response caching"""
    der_data = create_der_request_with_serial(100)

    response1 = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )

    response2 = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )

    assert response1 == response2


def test_ocsp_response_with_cache_disabled(ocsp_test_env):
    """Test OCSP response when cache TTL is 0"""
    der_data = create_der_request_with_serial(100)

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=0
    )
    assert response is not None


def test_ocsp_response_with_large_serial(ocsp_test_env):
    """Test OCSP response with large serial number"""
    large_serial = 0xFFFFFFFFFFFFFFFF
    der_data = create_der_request_with_serial(large_serial)

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )
    assert response is not None


def test_ocsp_response_with_nonce_data(ocsp_test_env):
    """Test OCSP response with nonce data in request"""
    # Create request with nonce-like data
    der_data = create_der_request_with_serial(100) + b'\x04\x10' + bytes(range(16))

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )
    assert response is not None


@patch('cryptography.x509.ocsp.OCSPResponseBuilder.sign')
def test_ocsp_response_signature_error(mock_sign, ocsp_test_env):
    """Test OCSP response when signing fails"""
    mock_sign.side_effect = Exception("Signing error")
    der_data = create_der_request_with_serial(100)

    response = build_ocsp_response(
        db_path=ocsp_test_env['db_path'],
        ca_cert=ocsp_test_env['ca_cert'],
        responder_cert=ocsp_test_env['ocsp_cert'],
        responder_key=ocsp_test_env['ocsp_key'],
        request_data=der_data,
        cache_ttl=60
    )
    assert response is not None