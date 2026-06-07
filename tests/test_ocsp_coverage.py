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
from micropki.database import init_db, insert_certificate, update_certificate_status


def create_ca_and_certificates():
    """Create CA, OCSP responder, and test certificate for OCSP testing"""
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

        # Create test certificate
        test_key = generate_rsa_key(2048)
        test_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
        test_cert = x509.CertificateBuilder() \
            .subject_name(test_subj) \
            .issuer_name(ca_subj) \
            .public_key(test_key.public_key()) \
            .serial_number(100) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=30)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(ca_key, hashes.SHA256())

        # Insert test certificate into DB
        cert_data = {
            'serial_hex': '64',
            'subject': test_subj.rfc4514_string(),
            'issuer': ca_subj.rfc4514_string(),
            'not_before': test_cert.not_valid_before_utc.isoformat(),
            'not_after': test_cert.not_valid_after_utc.isoformat(),
            'cert_pem': test_cert.public_bytes(serialization.Encoding.PEM).decode(),
            'status': 'valid',
            'created_at': now.isoformat()
        }
        insert_certificate(db_path, cert_data)

        return {
            'db_path': db_path,
            'ca_cert': ca_cert,
            'ocsp_key': ocsp_key,
            'ocsp_cert': ocsp_cert,
            'test_cert': test_cert
        }




def test_ocsp_build_response_with_nonce_extension():
    """Test OCSP response with nonce extension"""
    env = create_ca_and_certificates()

    # Create request with nonce pattern
    request_der = b'0B0@0>0<0:0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14test\x04\x14test\x02\x01d'

    response = build_ocsp_response(
        db_path=env['db_path'],
        ca_cert=env['ca_cert'],
        responder_cert=env['ocsp_cert'],
        responder_key=env['ocsp_key'],
        request_data=request_der,
        cache_ttl=60
    )
    assert response is not None


def test_ocsp_compute_issuer_hashes():
    """Test compute_issuer_hashes function"""
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
    assert name_hash != key_hash


def test_ocsp_build_response_error_handling():
    """Test OCSP response error handling"""
    env = create_ca_and_certificates()

    # Empty request data
    response = build_ocsp_response(
        db_path=env['db_path'],
        ca_cert=env['ca_cert'],
        responder_cert=env['ocsp_cert'],
        responder_key=env['ocsp_key'],
        request_data=b'',
        cache_ttl=60
    )
    assert response is not None


def test_ocsp_build_response_invalid_serial():
    """Test OCSP response with invalid serial number in request"""
    env = create_ca_and_certificates()

    # Request with invalid serial (non-hex)
    request_der = b'INVALID'

    response = build_ocsp_response(
        db_path=env['db_path'],
        ca_cert=env['ca_cert'],
        responder_cert=env['ocsp_cert'],
        responder_key=env['ocsp_key'],
        request_data=request_der,
        cache_ttl=60
    )
    assert response is not None