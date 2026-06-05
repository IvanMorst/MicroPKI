import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import generate_rsa_key
from micropki.validation import build_chain, validate_certificate


def test_build_chain_no_issuer():
    """Test chain building when no issuer found."""
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
        .sign(key, hashes.SHA256())

    chain = build_chain(cert, [], [])
    assert chain is None


def test_validate_certificate_no_key_usage():
    """Test certificate validation without KeyUsage extension - should fail."""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
    now = datetime.now(timezone.utc)

    # Create certificate WITHOUT KeyUsage
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now - timedelta(days=1)) \
        .not_valid_after(now + timedelta(days=1)) \
        .sign(key, hashes.SHA256())

    # Validation should fail because KeyUsage is required for CA certs
    valid, errors = validate_certificate(cert, issuer=cert, is_ca_expected=True)
    # Without KeyUsage, it should fail
    assert valid is False
    assert len(errors) > 0
    # Check that error message indicates missing KeyUsage or BasicConstraints
    # The actual error might be about missing BasicConstraints for CA cert
    assert any("KeyUsage" in err or "BasicConstraints" in err for err in errors)


def test_validate_certificate_with_key_usage():
    """Test certificate validation WITH KeyUsage extension."""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)

    # Create certificate WITH KeyUsage
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    )

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now - timedelta(days=1)) \
        .not_valid_after(now + timedelta(days=1)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(key_usage, critical=True) \
        .sign(key, hashes.SHA256())

    # Should pass because certificate is valid
    valid, errors = validate_certificate(cert, issuer=cert, is_ca_expected=True)
    assert valid is True
    assert len(errors) == 0


def test_validate_certificate_wrong_ca_flag():
    """Test certificate validation with wrong CA flag."""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
    now = datetime.now(timezone.utc)

    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )

    # Create certificate with CA=FALSE
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now - timedelta(days=1)) \
        .not_valid_after(now + timedelta(days=1)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .add_extension(key_usage, critical=True) \
        .sign(key, hashes.SHA256())

    # Expected CA but got non-CA
    valid, errors = validate_certificate(cert, issuer=cert, is_ca_expected=True)
    assert valid is False
    assert any("CA=FALSE" in err for err in errors)


def test_validate_end_entity_certificate_no_ca_flag():
    """Test end-entity certificate validation (CA=FALSE expected but CA=TRUE is okay? Actually CA=FALSE)."""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test EE")])
    now = datetime.now(timezone.utc)

    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )

    # Create end-entity certificate (CA=FALSE)
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now - timedelta(days=1)) \
        .not_valid_after(now + timedelta(days=1)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .add_extension(key_usage, critical=True) \
        .sign(key, hashes.SHA256())

    # Should pass (end-entity, not expected to be CA)
    valid, errors = validate_certificate(cert, issuer=cert, is_ca_expected=False)
    assert valid is True
    assert len(errors) == 0