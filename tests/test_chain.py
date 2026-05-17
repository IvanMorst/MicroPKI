import os
import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from micropki.crypto_utils import generate_rsa_key
from micropki.certificates import create_self_signed_cert, parse_dn
from micropki.chain import validate_chain, verify_signature


@pytest.fixture
def root_ca():
    """Create a self-signed root CA for testing."""
    key = generate_rsa_key(2048)
    subject = parse_dn("/CN=Test Root CA")
    cert = create_self_signed_cert(key, subject, 365, 'rsa')
    return key, cert


@pytest.fixture
def intermediate_ca(root_ca):
    """Create an intermediate CA signed by root."""
    root_key, root_cert = root_ca

    # Generate intermediate key
    inter_key = generate_rsa_key(2048)
    subject = parse_dn("/CN=Test Intermediate CA")

    # Build intermediate cert with proper serial number
    serial = int.from_bytes(os.urandom(19), byteorder='big')
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(inter_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=180))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True
    )

    # Add SKI
    ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    inter_cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
    return inter_key, inter_cert


@pytest.fixture
def leaf_cert(intermediate_ca):
    """Create a leaf certificate signed by intermediate."""
    inter_key, inter_cert = intermediate_ca

    # Generate leaf key
    leaf_key = generate_rsa_key(2048)
    subject = parse_dn("/CN=test.example.com")

    # Build leaf cert with proper serial number
    serial = int.from_bytes(os.urandom(19), byteorder='big')
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(inter_cert.subject)
    builder = builder.public_key(leaf_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=30))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )

    # Add SKI
    ski = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    leaf_cert = builder.sign(private_key=inter_key, algorithm=hashes.SHA256())
    return leaf_key, leaf_cert


@pytest.fixture
def leaf_cert_signed_by_root(root_ca):
    """Create a leaf certificate signed directly by root."""
    root_key, root_cert = root_ca

    # Generate leaf key
    leaf_key = generate_rsa_key(2048)
    subject = parse_dn("/CN=test-root.example.com")

    # Build leaf cert with proper serial number
    serial = int.from_bytes(os.urandom(19), byteorder='big')
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(leaf_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=30))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )

    leaf_cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
    return leaf_key, leaf_cert


def test_verify_signature(root_ca):
    """Test signature verification function."""
    key, cert = root_ca
    # Self-signed certificate should verify with itself
    # Используем публичный ключ самого сертификата
    result = verify_signature(cert, cert)
    assert result is True


def test_validate_chain_with_intermediate(root_ca, intermediate_ca, leaf_cert):
    """Test full chain validation with intermediate CA."""
    root_key, root_cert = root_ca
    inter_key, inter_cert = intermediate_ca
    leaf_key, leaf_cert = leaf_cert

    # Valid chain should pass
    assert validate_chain(leaf_cert, [inter_cert], root_cert)


def test_validate_chain_without_intermediate(root_ca, leaf_cert_signed_by_root):
    """Test chain validation without intermediate CA."""
    root_key, root_cert = root_ca
    leaf_key, leaf_cert = leaf_cert_signed_by_root

    # Chain with leaf signed directly by root should pass (empty intermediates list)
    assert validate_chain(leaf_cert, [], root_cert)


def test_validate_chain_missing_intermediate_fails(root_ca, leaf_cert):
    """Test that missing intermediate when needed fails validation."""
    root_key, root_cert = root_ca
    leaf_key, leaf_cert = leaf_cert

    # This chain should fail because leaf is signed by intermediate,
    # but intermediate is not provided
    assert not validate_chain(leaf_cert, [], root_cert)


def test_validate_chain_wrong_intermediate_fails(root_ca, intermediate_ca, leaf_cert):
    """Test that wrong intermediate fails validation."""
    root_key, root_cert = root_ca
    inter_key, inter_cert = intermediate_ca
    leaf_key, leaf_cert = leaf_cert

    # Create another intermediate
    wrong_key = generate_rsa_key(2048)
    wrong_subject = parse_dn("/CN=Wrong Intermediate")
    wrong_builder = x509.CertificateBuilder()
    wrong_builder = wrong_builder.subject_name(wrong_subject)
    wrong_builder = wrong_builder.issuer_name(root_cert.subject)
    wrong_builder = wrong_builder.public_key(wrong_key.public_key())
    wrong_builder = wrong_builder.serial_number(int.from_bytes(os.urandom(19), byteorder='big'))
    wrong_builder = wrong_builder.not_valid_before(datetime.now(timezone.utc))
    wrong_builder = wrong_builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=180))
    wrong_builder = wrong_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    )
    wrong_inter = wrong_builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # Should fail because wrong intermediate doesn't sign the leaf
    assert not validate_chain(leaf_cert, [wrong_inter], root_cert)


def test_validate_chain_expired_cert_fails(root_ca):
    """Test that expired certificate fails validation."""
    root_key, root_cert = root_ca

    # Create expired leaf
    leaf_key = generate_rsa_key(2048)
    subject = parse_dn("/CN=expired.example.com")

    # Set validity in the past
    now = datetime.now(timezone.utc)
    past = now - timedelta(days=400)
    more_past = past - timedelta(days=30)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(leaf_key.public_key())
    builder = builder.serial_number(int.from_bytes(os.urandom(19), byteorder='big'))
    builder = builder.not_valid_before(more_past)
    builder = builder.not_valid_after(past)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    expired_cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # Should fail because certificate is expired
    assert not validate_chain(expired_cert, [], root_cert)
