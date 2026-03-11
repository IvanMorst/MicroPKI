import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from micropki.crypto_utils import generate_rsa_key
from micropki.certificates import parse_dn
from micropki.csr import generate_csr, parse_san_string, save_csr, load_csr


def test_generate_csr(tmp_path):
    key = generate_rsa_key(2048)
    subject = parse_dn("/CN=Test Intermediate")

    csr = generate_csr(key, subject, is_ca=True, pathlen=0)
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test Intermediate"

    # Check for BasicConstraints extension
    bc = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.value.ca
    assert bc.value.path_length == 0

    # Test save/load
    csr_path = tmp_path / "test.csr.pem"
    save_csr(csr, csr_path)
    assert csr_path.exists()

    loaded_csr = load_csr(csr_path)
    assert loaded_csr.subject == csr.subject


def test_parse_san_string():
    dns = parse_san_string('dns:example.com')
    assert isinstance(dns, x509.DNSName)
    assert dns.value == 'example.com'

    ip = parse_san_string('ip:192.168.1.1')
    assert isinstance(ip, x509.IPAddress)
    assert str(ip.value) == '192.168.1.1'

    email = parse_san_string('email:test@example.com')
    assert isinstance(email, x509.RFC822Name)
    assert email.value == 'test@example.com'

    uri = parse_san_string('uri:https://example.com')
    assert isinstance(uri, x509.UniformResourceIdentifier)
    assert uri.value == 'https://example.com'

    with pytest.raises(ValueError, match="Invalid SAN format"):
        parse_san_string('invalid')

    with pytest.raises(ValueError, match="Invalid IP address"):
        parse_san_string('ip:not.an.ip')

    with pytest.raises(ValueError, match="Unsupported SAN type"):
        parse_san_string('unsupported:value')