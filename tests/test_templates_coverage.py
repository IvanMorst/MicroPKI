import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from micropki.templates import get_template, ServerTemplate, ClientTemplate, CodeSigningTemplate, TemplateType


def test_get_template_server():
    """Test get_template returns ServerTemplate"""
    template = get_template('server')
    assert isinstance(template, ServerTemplate)
    assert template.type == TemplateType.SERVER


def test_get_template_client():
    """Test get_template returns ClientTemplate"""
    template = get_template('client')
    assert isinstance(template, ClientTemplate)
    assert template.type == TemplateType.CLIENT


def test_get_template_code_signing():
    """Test get_template returns CodeSigningTemplate"""
    template = get_template('code_signing')
    assert isinstance(template, CodeSigningTemplate)
    assert template.type == TemplateType.CODE_SIGNING


def test_get_template_invalid():
    """Test get_template with invalid name"""
    with pytest.raises(ValueError, match="Unknown template"):
        get_template('invalid')


def test_server_template_key_usage_rsa():
    """Test server template key usage for RSA"""
    template = ServerTemplate()
    ku = template.get_key_usage('rsa')
    assert ku.digital_signature is True
    assert ku.key_encipherment is True
    assert ku.key_cert_sign is False


def test_server_template_key_usage_ecc():
    """Test server template key usage for ECC"""
    template = ServerTemplate()
    ku = template.get_key_usage('ecc')
    assert ku.digital_signature is True
    assert ku.key_agreement is True
    assert ku.key_encipherment is False


def test_server_template_eku():
    """Test server template extended key usage"""
    template = ServerTemplate()
    eku = template.get_extended_key_usage()
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_client_template_eku():
    """Test client template extended key usage"""
    template = ClientTemplate()
    eku = template.get_extended_key_usage()
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_code_signing_template_eku():
    """Test code signing template extended key usage"""
    template = CodeSigningTemplate()
    eku = template.get_extended_key_usage()
    assert ExtendedKeyUsageOID.CODE_SIGNING in eku


def test_server_template_san_validation():
    """Test server template SAN validation"""
    template = ServerTemplate()
    from micropki.csr import parse_san_string
    dns_san = parse_san_string('dns:example.com')
    ip_san = parse_san_string('ip:192.168.1.1')
    email_san = parse_san_string('email:test@example.com')

    assert template.validate_san_types([dns_san]) is True
    assert template.validate_san_types([ip_san]) is True
    assert template.validate_san_types([dns_san, ip_san]) is True
    assert template.validate_san_types([email_san]) is False


def test_client_template_san_validation():
    """Test client template SAN validation"""
    template = ClientTemplate()
    from micropki.csr import parse_san_string
    dns_san = parse_san_string('dns:client.example.com')
    email_san = parse_san_string('email:client@example.com')
    uri_san = parse_san_string('uri:https://example.com')

    assert template.validate_san_types([dns_san]) is True
    assert template.validate_san_types([email_san]) is True
    assert template.validate_san_types([uri_san]) is True