import pytest
from micropki.policy import validate_key_size, validate_validity_days, validate_san_types


def test_key_size_validation():
    valid, msg = validate_key_size(2048, 'end_entity', 'rsa')
    assert valid

    valid, msg = validate_key_size(1024, 'end_entity', 'rsa')
    assert not valid

    valid, msg = validate_key_size(256, 'end_entity', 'ecc')
    assert valid

    valid, msg = validate_key_size(224, 'end_entity', 'ecc')
    assert not valid


def test_validity_validation():
    valid, msg = validate_validity_days(365, 'end_entity')
    assert valid

    valid, msg = validate_validity_days(400, 'end_entity')
    assert not valid


def test_san_validation():
    from cryptography import x509
    san_list = [x509.DNSName("example.com")]
    valid, msg = validate_san_types(san_list, 'server')
    assert valid

    san_list = [x509.RFC822Name("test@example.com")]
    valid, msg = validate_san_types(san_list, 'server')
    assert not valid