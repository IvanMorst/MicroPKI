import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

from micropki.chain import verify_signature, validate_chain, print_chain_info
from micropki.crypto_utils import generate_rsa_key


def create_test_chain():
    """Create a complete certificate chain for testing"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.now(timezone.utc)

    root_cert = x509.CertificateBuilder() \
        .subject_name(root_subj) \
        .issuer_name(root_subj) \
        .public_key(root_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(root_key, hashes.SHA256())

    inter_key = generate_rsa_key(2048)
    inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    inter_cert = x509.CertificateBuilder() \
        .subject_name(inter_subj) \
        .issuer_name(root_subj) \
        .public_key(inter_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(root_key, hashes.SHA256())

    leaf_key = generate_rsa_key(2048)
    leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf Cert")])
    leaf_cert = x509.CertificateBuilder() \
        .subject_name(leaf_subj) \
        .issuer_name(inter_subj) \
        .public_key(leaf_key.public_key()) \
        .serial_number(3) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=30)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .sign(inter_key, hashes.SHA256())

    return leaf_cert, [inter_cert], root_cert


def test_validate_chain_without_ca_constraints():
    """Test chain validation when CA missing BasicConstraints"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.now(timezone.utc)

    # Root without BasicConstraints (should fail)
    root_cert = x509.CertificateBuilder() \
        .subject_name(root_subj) \
        .issuer_name(root_subj) \
        .public_key(root_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .sign(root_key, hashes.SHA256())

    leaf_key = generate_rsa_key(2048)
    leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
    leaf_cert = x509.CertificateBuilder() \
        .subject_name(leaf_subj) \
        .issuer_name(root_subj) \
        .public_key(leaf_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=30)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .sign(root_key, hashes.SHA256())

    result = validate_chain(leaf_cert, [], root_cert)
    assert result is False


def test_validate_chain_with_non_ca_intermediate():
    """Test chain validation when intermediate is not a CA"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.now(timezone.utc)

    root_cert = x509.CertificateBuilder() \
        .subject_name(root_subj) \
        .issuer_name(root_subj) \
        .public_key(root_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(root_key, hashes.SHA256())

    # Intermediate without CA flag (CA=FALSE)
    inter_key = generate_rsa_key(2048)
    inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Not CA")])
    inter_cert = x509.CertificateBuilder() \
        .subject_name(inter_subj) \
        .issuer_name(root_subj) \
        .public_key(inter_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .sign(root_key, hashes.SHA256())

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
        .sign(inter_key, hashes.SHA256())

    result = validate_chain(leaf_cert, [inter_cert], root_cert)
    assert result is False


