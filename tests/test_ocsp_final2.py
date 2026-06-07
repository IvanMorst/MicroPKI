import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from micropki.ocsp import build_ocsp_response, compute_issuer_hashes
from micropki.crypto_utils import generate_rsa_key
from micropki.database import init_db, insert_certificate, update_certificate_status


def create_ca_certificate():
    """Helper to create CA certificate"""
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
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False) \
        .sign(ca_key, hashes.SHA256())

    return ocsp_key, ocsp_cert


def create_test_certificate(ca_key, ca_cert, serial_num, subject_name, status='valid'):
    """Helper to create test certificate with DB entry"""
    cert_key = generate_rsa_key(2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    now = datetime.now(timezone.utc)

    cert = x509.CertificateBuilder() \
        .subject_name(subj) \
        .issuer_name(ca_cert.subject) \
        .public_key(cert_key.public_key()) \
        .serial_number(serial_num) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=30)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .sign(ca_key, hashes.SHA256())

    return cert_key, cert


def create_ocsp_request(serial_number, issuer_cert, cert):
    """Helper to create OCSP request"""
    from cryptography.x509.ocsp import OCSPRequestBuilder
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
    request = builder.build()
    return request.public_bytes(serialization.Encoding.DER)


def test_ocsp_build_response_for_valid_certificate():
    """Test OCSP response for a valid certificate"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)
        cert_key, test_cert = create_test_certificate(ca_key, ca_cert, 100, "Test Cert 1")

        cert_data = {
            'serial_hex': format(100, 'X'),
            'subject': "CN=Test Cert 1",
            'issuer': ca_cert.subject.rfc4514_string(),
            'not_before': test_cert.not_valid_before_utc.isoformat(),
            'not_after': test_cert.not_valid_after_utc.isoformat(),
            'cert_pem': test_cert.public_bytes(serialization.Encoding.PEM).decode(),
            'status': 'valid',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        insert_certificate(db_path, cert_data)

        request_der = create_ocsp_request(100, ca_cert, test_cert)

        response_der = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=request_der,
            cache_ttl=60
        )

        assert response_der is not None
        assert len(response_der) > 0


def test_ocsp_build_response_for_revoked_certificate():
    """Test OCSP response for a revoked certificate"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)
        cert_key, test_cert = create_test_certificate(ca_key, ca_cert, 200, "Test Cert 2")

        cert_data = {
            'serial_hex': format(200, 'X'),
            'subject': "CN=Test Cert 2",
            'issuer': ca_cert.subject.rfc4514_string(),
            'not_before': test_cert.not_valid_before_utc.isoformat(),
            'not_after': test_cert.not_valid_after_utc.isoformat(),
            'cert_pem': test_cert.public_bytes(serialization.Encoding.PEM).decode(),
            'status': 'valid',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        insert_certificate(db_path, cert_data)

        update_certificate_status(db_path, format(200, 'X'), 'revoked', 'keyCompromise')

        request_der = create_ocsp_request(200, ca_cert, test_cert)

        response_der = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=request_der,
            cache_ttl=60
        )

        assert response_der is not None
        assert len(response_der) > 0


def test_ocsp_build_response_for_unknown_certificate():
    """Test OCSP response for an unknown certificate (not in DB)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)

        cert_key, unknown_cert = create_test_certificate(ca_key, ca_cert, 999, "Unknown Cert")

        request_der = create_ocsp_request(999, ca_cert, unknown_cert)

        response_der = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=request_der,
            cache_ttl=60
        )

        assert response_der is not None
        assert len(response_der) > 0


def test_ocsp_build_response_with_different_issuer():
    """Test OCSP response when request has different issuer"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)

        other_ca_key, other_ca_cert = create_ca_certificate()
        cert_key, test_cert = create_test_certificate(other_ca_key, other_ca_cert, 300, "Other CA Cert")

        cert_data = {
            'serial_hex': format(300, 'X'),
            'subject': "CN=Other CA Cert",
            'issuer': other_ca_cert.subject.rfc4514_string(),
            'not_before': test_cert.not_valid_before_utc.isoformat(),
            'not_after': test_cert.not_valid_after_utc.isoformat(),
            'cert_pem': test_cert.public_bytes(serialization.Encoding.PEM).decode(),
            'status': 'valid',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        insert_certificate(db_path, cert_data)

        request_der = create_ocsp_request(300, other_ca_cert, test_cert)

        response_der = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=request_der,
            cache_ttl=60
        )

        assert response_der is not None
        assert len(response_der) > 0


def test_ocsp_build_response_with_empty_request():
    """Test OCSP response with empty request data"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)

        empty_request = b''

        response_der = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=empty_request,
            cache_ttl=60
        )

        assert response_der is not None
        assert len(response_der) > 0


def test_ocsp_build_response_parse_error():
    """Test OCSP response when request parsing fails"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)

        # Pass invalid data that will cause parse error
        invalid_data = b'INVALID\x00DER\x01DATA'

        response_der = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=invalid_data,
            cache_ttl=60
        )

        assert response_der is not None
        assert len(response_der) > 0


def test_ocsp_build_response_cache_hit():
    """Test OCSP response cache functionality"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        ca_key, ca_cert = create_ca_certificate()
        ocsp_key, ocsp_cert = create_ocsp_responder_certificate(ca_key, ca_cert)
        cert_key, test_cert = create_test_certificate(ca_key, ca_cert, 500, "Cache Test")

        cert_data = {
            'serial_hex': format(500, 'X'),
            'subject': "CN=Cache Test",
            'issuer': ca_cert.subject.rfc4514_string(),
            'not_before': test_cert.not_valid_before_utc.isoformat(),
            'not_after': test_cert.not_valid_after_utc.isoformat(),
            'cert_pem': test_cert.public_bytes(serialization.Encoding.PEM).decode(),
            'status': 'valid',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        insert_certificate(db_path, cert_data)

        request_der = create_ocsp_request(500, ca_cert, test_cert)

        response1 = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=request_der,
            cache_ttl=60
        )

        response2 = build_ocsp_response(
            db_path=db_path,
            ca_cert=ca_cert,
            responder_cert=ocsp_cert,
            responder_key=ocsp_key,
            request_data=request_der,
            cache_ttl=60
        )

        assert response1 == response2