import pytest
from cryptography import x509
from micropki.templates import (
    ServerTemplate, ClientTemplate, CodeSigningTemplate,
    TemplateType, get_template
)
from micropki.csr import parse_san_string


def test_server_template():
    template = ServerTemplate()
    assert template.type == TemplateType.SERVER
    assert template.type.value == 'server'

    # Test key usage
    ku_rsa = template.get_key_usage('rsa')
    assert ku_rsa.digital_signature
    assert ku_rsa.key_encipherment
    assert not ku_rsa.key_cert_sign

    ku_ecc = template.get_key_usage('ecc')
    assert ku_ecc.digital_signature
    assert ku_ecc.key_agreement
    assert not ku_ecc.key_encipherment

    # Test EKU - используем правильный способ доступа
    eku = template.get_extended_key_usage()
    # Получаем список OID из расширения
    eku_oids = list(eku)
    assert len(eku_oids) == 1
    assert eku_oids[0].dotted_string == '1.3.6.1.5.5.7.3.1'  # serverAuth

def test_client_template():
    template = ClientTemplate()
    assert template.type == TemplateType.CLIENT
    assert template.type.value == 'client'

    ku = template.get_key_usage('rsa')
    assert ku.digital_signature
    assert not ku.key_cert_sign
    assert ku.key_agreement

    eku = template.get_extended_key_usage()
    eku_oids = list(eku)
    assert len(eku_oids) == 1
    assert eku_oids[0].dotted_string == '1.3.6.1.5.5.7.3.2'  # clientAuth

def test_code_signing_template():
    template = CodeSigningTemplate()
    assert template.type == TemplateType.CODE_SIGNING
    assert template.type.value == 'code_signing'

    ku = template.get_key_usage('rsa')
    assert ku.digital_signature
    assert not ku.key_encipherment
    assert not ku.key_cert_sign
    assert not ku.key_agreement

    eku = template.get_extended_key_usage()
    eku_oids = list(eku)
    assert len(eku_oids) == 1
    assert eku_oids[0].dotted_string == '1.3.6.1.5.5.7.3.3'