import pytest
from cryptography import x509
from cryptography.hazmat._oid import NameOID

from micropki.certificates import parse_dn


def test_parse_dn_comma():
    dn_str = "CN=Test Root,O=Example,C=US"
    name = parse_dn(dn_str)
    attrs = list(name)
    assert len(attrs) == 3

    # Находим CN по OID, а не по позиции (порядок может быть разным)
    cn_attrs = [attr for attr in attrs if attr.oid == NameOID.COMMON_NAME]
    o_attrs = [attr for attr in attrs if attr.oid == NameOID.ORGANIZATION_NAME]
    c_attrs = [attr for attr in attrs if attr.oid == NameOID.COUNTRY_NAME]

    assert len(cn_attrs) == 1
    assert cn_attrs[0].value == 'Test Root'
    assert len(o_attrs) == 1
    assert o_attrs[0].value == 'Example'
    assert len(c_attrs) == 1
    assert c_attrs[0].value == 'US'


# Также обновляем test_parse_dn_slash для консистентности
def test_parse_dn_slash():
    dn_str = "/CN=Test Root/O=Example/C=US"
    name = parse_dn(dn_str)
    attrs = list(name)
    assert len(attrs) == 3

    cn_attrs = [attr for attr in attrs if attr.oid == NameOID.COMMON_NAME]
    o_attrs = [attr for attr in attrs if attr.oid == NameOID.ORGANIZATION_NAME]
    c_attrs = [attr for attr in attrs if attr.oid == NameOID.COUNTRY_NAME]

    assert len(cn_attrs) == 1
    assert cn_attrs[0].value == 'Test Root'
    assert len(o_attrs) == 1
    assert o_attrs[0].value == 'Example'
    assert len(c_attrs) == 1
    assert c_attrs[0].value == 'US'

def test_parse_dn_invalid():
    with pytest.raises(ValueError):
        parse_dn("/CN=Test/foo")  # missing equals
    with pytest.raises(ValueError):
        parse_dn("CN=Test,XX=Invalid")  # unsupported attribute