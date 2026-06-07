import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from micropki.chain import verify_signature, validate_chain, print_chain_info
from micropki.crypto_utils import generate_rsa_key


def create_certificate(key, subject, issuer_subj, issuer_key, serial, ca=False):
    """Helper to create certificate"""
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer_subj) \
        .public_key(key.public_key()) \
        .serial_number(serial) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365))

    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    return builder.sign(issuer_key, hashes.SHA256())


def test_verify_signature_general_exception():
    """Test signature verification with general exception"""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    cert = create_certificate(key, subject, subject, key, 1, ca=True)

    # Создаём неправильный сертификат, который вызовет ошибку верификации
    wrong_key = generate_rsa_key(2048)
    wrong_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong")])
    wrong_cert = create_certificate(wrong_key, wrong_subj, wrong_subj, wrong_key, 2, ca=True)

    # Подпись неправильная - должна вернуть False
    result = verify_signature(cert, wrong_cert)
    assert result is False


def test_validate_chain_with_expired_intermediate():
    """Test chain validation with expired intermediate certificate"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
    now = datetime.now(timezone.utc)

    # Root is valid
    root_cert = x509.CertificateBuilder() \
        .subject_name(root_subj) \
        .issuer_name(root_subj) \
        .public_key(root_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now - timedelta(days=400)) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(root_key, hashes.SHA256())

    # Intermediate is expired
    inter_key = generate_rsa_key(2048)
    inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate")])
    inter_cert = x509.CertificateBuilder() \
        .subject_name(inter_subj) \
        .issuer_name(root_subj) \
        .public_key(inter_key.public_key()) \
        .serial_number(2) \
        .not_valid_before(now - timedelta(days=400)) \
        .not_valid_after(now - timedelta(days=1)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
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
    # Should fail because intermediate is expired
    assert result is False


def test_print_chain_info_with_intermediate():
    """Test print_chain_info with intermediate certificates"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
    root_cert = create_certificate(root_key, root_subj, root_subj, root_key, 1, ca=True)

    inter_key = generate_rsa_key(2048)
    inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate")])
    inter_cert = create_certificate(inter_key, inter_subj, root_subj, root_key, 2, ca=True)

    leaf_key = generate_rsa_key(2048)
    leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
    leaf_cert = create_certificate(leaf_key, leaf_subj, inter_subj, inter_key, 3, ca=False)

    # Call the function - just verify it doesn't crash
    try:
        print_chain_info(leaf_cert, [inter_cert], root_cert)
        assert True
    except Exception as e:
        assert False, f"print_chain_info raised exception: {e}"