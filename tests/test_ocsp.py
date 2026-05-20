import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from micropki.database import init_db, insert_certificate, update_certificate_status
from micropki.crypto_utils import generate_rsa_key
from micropki.ocsp import build_ocsp_response, compute_issuer_hashes


def create_ca_certificate(key, subject, serial):
    """Create a CA certificate."""
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    return builder.sign(key, hashes.SHA256())


def create_ocsp_certificate(key, subject, issuer_key, issuer_cert, serial):
    """Create an OCSP responder certificate."""
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    return builder.sign(issuer_key, hashes.SHA256())


def create_end_entity_certificate(key, subject, issuer_key, issuer_cert, serial):
    """Create an end-entity certificate."""
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=30))
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def test_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        # Create CA
        ca_key = generate_rsa_key(2048)
        ca_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        ca_cert = create_ca_certificate(ca_key, ca_subj, 1)

        # Create OCSP responder cert
        ocsp_key = generate_rsa_key(2048)
        ocsp_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")])
        ocsp_cert = create_ocsp_certificate(ocsp_key, ocsp_subj, ca_key, ca_cert, 2)

        # Create test end-entity certificate
        ee_key = generate_rsa_key(2048)
        ee_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
        ee_cert = create_end_entity_certificate(ee_key, ee_subj, ca_key, ca_cert, 3)

        # Insert test certificate into database
        cert_data = {
            'serial_hex': format(ee_cert.serial_number, 'X'),
            'subject': ee_subj.rfc4514_string(),
            'issuer': ca_subj.rfc4514_string(),
            'not_before': ee_cert.not_valid_before_utc.isoformat(),
            'not_after': ee_cert.not_valid_after_utc.isoformat(),
            'cert_pem': 'DUMMY',
            'status': 'valid',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        insert_certificate(db_path, cert_data)

        yield {
            'db_path': db_path,
            'ca_cert': ca_cert,
            'ca_key': ca_key,
            'responder_cert': ocsp_cert,
            'responder_key': ocsp_key,
            'test_cert': ee_cert,
            'test_serial': format(ee_cert.serial_number, 'X')
        }


def test_compute_issuer_hashes(test_env):
    name_hash, key_hash = compute_issuer_hashes(test_env['ca_cert'])
    assert len(name_hash) == 20
    assert len(key_hash) == 20


def test_build_ocsp_response_valid(test_env):
    # Build request with proper serial number
    from cryptography.x509.ocsp import OCSPRequestBuilder

    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(
        test_env['test_cert'],
        test_env['ca_cert'],
        hashes.SHA1()
    )
    ocsp_request = builder.build()
    request_der = ocsp_request.public_bytes(serialization.Encoding.DER)

    response_der = build_ocsp_response(
        db_path=test_env['db_path'],
        ca_cert=test_env['ca_cert'],
        responder_cert=test_env['responder_cert'],
        responder_key=test_env['responder_key'],
        request_data=request_der,
        cache_ttl=60
    )

    assert response_der is not None
    assert len(response_der) > 0


def test_build_ocsp_response_revoked(test_env):
    # Revoke the certificate
    update_certificate_status(test_env['db_path'], test_env['test_serial'], 'revoked', 'keyCompromise')

    from cryptography.x509.ocsp import OCSPRequestBuilder

    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(
        test_env['test_cert'],
        test_env['ca_cert'],
        hashes.SHA1()
    )
    ocsp_request = builder.build()
    request_der = ocsp_request.public_bytes(serialization.Encoding.DER)

    response_der = build_ocsp_response(
        db_path=test_env['db_path'],
        ca_cert=test_env['ca_cert'],
        responder_cert=test_env['responder_cert'],
        responder_key=test_env['responder_key'],
        request_data=request_der,
        cache_ttl=60
    )

    assert response_der is not None
    assert len(response_der) > 0


def test_build_ocsp_response_unknown(test_env):
    # Query non-existent certificate
    from cryptography.x509.ocsp import OCSPRequestBuilder

    # Create a fake cert with unknown serial
    fake_key = generate_rsa_key(2048)
    fake_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Cert")])
    fake_cert = create_end_entity_certificate(fake_key, fake_subj, test_env['ca_key'], test_env['ca_cert'], 999999)

    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(fake_cert, test_env['ca_cert'], hashes.SHA1())
    ocsp_request = builder.build()
    request_der = ocsp_request.public_bytes(serialization.Encoding.DER)

    response_der = build_ocsp_response(
        db_path=test_env['db_path'],
        ca_cert=test_env['ca_cert'],
        responder_cert=test_env['responder_cert'],
        responder_key=test_env['responder_key'],
        request_data=request_der,
        cache_ttl=60
    )

    assert response_der is not None
    assert len(response_der) > 0
