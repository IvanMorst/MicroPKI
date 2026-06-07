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
from micropki.database import init_db, insert_certificate


def create_ca_certificate():
    """Helper to create CA certificate for OCSP testing"""
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

    return ca_key, ca_cert


def create_ocsp_responder_certificate(ca_key, ca_cert):
    """Helper to create OCSP responder certificate"""
    ocsp_key = generate_rsa_key(2048)
    ocsp_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")])
    now = datetime.now(timezone.utc)

    ocsp_cert = x509.CertificateBuilder() \
        .subject_name(ocsp_subj) \
        .issuer_name(ca_cert.subject) \
        .public_key(ocsp_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .sign(ca_key, hashes.SHA256())

    return ocsp_key, ocsp_cert


def test_compute_issuer_hashes():
    """Test compute_issuer_hashes function"""
    _, ca_cert = create_ca_certificate()
    name_hash, key_hash = compute_issuer_hashes(ca_cert)
    assert len(name_hash) == 20
    assert len(key_hash) == 20


def test_build_ocsp_response_malformed_request():
    """Test OCSP response with malformed request"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)

        # Send malformed request (invalid DER)
        malformed_data = b'INVALID DER DATA'

        response = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=malformed_data,
            cache_ttl=60
        )
        assert response is not None
        assert len(response) > 0


@patch('micropki.ocsp.OCSPRequestBuilder')
def test_build_ocsp_response_exception_handling(mock_builder):
    """Test OCSP response exception handling"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)

        # Mock builder to raise exception
        mock_builder.side_effect = Exception("Builder error")

        response = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=b'some data',
            cache_ttl=60
        )
        assert response is not None