import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import generate_rsa_key
from micropki.validation import build_chain, validate_chain, validate_certificate


def create_chain():
    """Helper to create a valid chain root->intermediate->leaf"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.now(timezone.utc)

    ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())

    root_cert = x509.CertificateBuilder() \
        .subject_name(root_subj) \
        .issuer_name(root_subj) \
        .public_key(root_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True) \
        .add_extension(ski, critical=False) \
        .add_extension(aki, critical=False) \
        .sign(root_key, hashes.SHA256())

    inter_key = generate_rsa_key(2048)
    inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    inter_ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())

    inter_cert = x509.CertificateBuilder() \
        .subject_name(inter_subj) \
        .issuer_name(root_subj) \
        .public_key(inter_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True) \
        .add_extension(inter_ski, critical=False) \
        .add_extension(aki, critical=False) \
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
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                     content_commitment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True) \
        .sign(inter_key, hashes.SHA256())

    return leaf_cert, [inter_cert], [root_cert]


def test_validate_chain_success():
    """Test full chain validation success"""
    leaf, intermediates, roots = create_chain()
    result = validate_chain(leaf, intermediates, roots, check_revocation=False)
    assert result.success is True
    assert len(result.errors) == 0


def test_validate_chain_missing_leaf_basic_constraints():
    """Test leaf without BasicConstraints (should pass)"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.now(timezone.utc)

    ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())

    root_cert = x509.CertificateBuilder() \
        .subject_name(root_subj) \
        .issuer_name(root_subj) \
        .public_key(root_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True) \
        .add_extension(ski, critical=False) \
        .add_extension(aki, critical=False) \
        .sign(root_key, hashes.SHA256())

    leaf_key = generate_rsa_key(2048)
    leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
    # No BasicConstraints extension
    leaf_cert = x509.CertificateBuilder() \
        .subject_name(leaf_subj) \
        .issuer_name(root_subj) \
        .public_key(leaf_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=30)) \
        .sign(root_key, hashes.SHA256())

    result = validate_chain(leaf_cert, [], [root_cert], check_revocation=False)
    assert result.success is True


def test_validate_chain_root_missing_basic_constraints():
    """Test root without BasicConstraints (should fail)"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.now(timezone.utc)
    # No BasicConstraints extension
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

    result = validate_chain(leaf_cert, [], [root_cert], check_revocation=False)
    assert result.success is False
    # Check that the error message indicates missing BasicConstraints
    error_messages = ' '.join(result.errors).lower()
    assert 'basicconstraints' in error_messages or 'missing' in error_messages


def test_validate_chain_with_key_usage():
    """Test chain validation with proper KeyUsage"""
    leaf, intermediates, roots = create_chain()
    result = validate_chain(leaf, intermediates, roots, check_revocation=False)
    assert result.success is True


def test_build_chain_no_issuer():
    """Test chain building when no issuer found"""
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