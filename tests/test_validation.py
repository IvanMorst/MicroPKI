import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.validation import build_chain, validate_certificate, validate_chain
from micropki.crypto_utils import generate_rsa_key


def create_ca_certificate(key, subject, serial, is_ca=True):
    """Helper to create a CA certificate."""
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True if is_ca else False,
            crl_sign=True if is_ca else False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False
    )
    return builder.sign(key, hashes.SHA256())


def create_end_entity_certificate(key, subject, issuer_key, issuer_cert, serial):
    """Helper to create an end-entity certificate."""
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=30))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    return builder.sign(issuer_key, hashes.SHA256())


def test_build_chain():
    """Test chain building with root -> intermediate -> leaf."""
    # Create root CA
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
    root_cert = create_ca_certificate(root_key, root_subj, 1)

    # Create intermediate CA
    inter_key = generate_rsa_key(2048)
    inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate")])

    now = datetime.now(timezone.utc)
    inter_cert = x509.CertificateBuilder() \
        .subject_name(inter_subj) \
        .issuer_name(root_subj) \
        .public_key(inter_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ) \
        .sign(root_key, hashes.SHA256())

    # Create leaf certificate
    leaf_key = generate_rsa_key(2048)
    leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
    leaf_cert = x509.CertificateBuilder() \
        .subject_name(leaf_subj) \
        .issuer_name(inter_subj) \
        .public_key(leaf_key.public_key()) \
        .serial_number(3) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=30)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ) \
        .sign(inter_key, hashes.SHA256())

    # Build chain
    chain = build_chain(leaf_cert, [inter_cert], [root_cert])
    assert chain is not None
    assert len(chain) == 3
    assert chain[0] == leaf_cert
    assert chain[1] == inter_cert
    assert chain[2] == root_cert


def test_validate_certificate_valid():
    """Test validation of a valid certificate."""
    key = generate_rsa_key(2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subj) \
        .issuer_name(subj) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now - timedelta(days=1)) \
        .not_valid_after(now + timedelta(days=1)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ) \
        .sign(key, hashes.SHA256())

    valid, errors = validate_certificate(cert, issuer=cert, is_ca_expected=True)
    assert valid, f"Validation failed with errors: {errors}"
    assert len(errors) == 0


def test_validate_certificate_expired():
    """Test validation of an expired certificate."""
    key = generate_rsa_key(2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subj) \
        .issuer_name(subj) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now - timedelta(days=10)) \
        .not_valid_after(now - timedelta(days=1)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ) \
        .sign(key, hashes.SHA256())

    valid, errors = validate_certificate(cert, issuer=cert, is_ca_expected=True)
    assert not valid
    assert any("expired" in err.lower() for err in errors)