import pytest
from cryptography import x509
from micropki.certificates import parse_dn, _attr_key_to_oid


def test_parse_dn_slash():
    dn_str = "/CN=Test Root/O=Example/C=US"
    name = parse_dn(dn_str)
    attrs = list(name)
    assert len(attrs) == 3
    assert attrs[0].oid == _attr_key_to_oid('CN')
    assert attrs[0].value == 'Test Root'
    assert attrs[1].oid == _attr_key_to_oid('O')
    assert attrs[1].value == 'Example'
    assert attrs[2].oid == _attr_key_to_oid('C')
    assert attrs[2].value == 'US'


def test_parse_dn_comma():
    dn_str = "CN=Test Root,O=Example,C=US"
    name = parse_dn(dn_str)
    attrs = list(name)
    assert len(attrs) == 3

    # Find attribute by OID instead of assuming order
    cn_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('CN')]
    o_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('O')]
    c_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('C')]

    assert len(cn_attrs) == 1
    assert cn_attrs[0].value == 'Test Root'
    assert len(o_attrs) == 1
    assert o_attrs[0].value == 'Example'
    assert len(c_attrs) == 1
    assert c_attrs[0].value == 'US'


def test_parse_dn_comma_with_escaped():
    """Test parsing comma-separated DN with escaped commas."""
    dn_str = "CN=Test\\, Root,O=Example,C=US"
    name = parse_dn(dn_str)
    attrs = list(name)
    assert len(attrs) == 3

    cn_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('CN')]
    # The value should be 'Test, Root' (without the backslash)
    assert cn_attrs[0].value == 'Test, Root'

    o_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('O')]
    assert o_attrs[0].value == 'Example'

    c_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('C')]
    assert c_attrs[0].value == 'US'


def test_parse_dn_comma_with_multiple_escaped():
    """Test parsing DN with multiple escaped characters."""
    dn_str = "CN=Test\\, Root\\, Inc.,O=Example\\, Corp.,C=US"
    name = parse_dn(dn_str)
    attrs = list(name)
    assert len(attrs) == 3

    cn_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('CN')]
    assert cn_attrs[0].value == 'Test, Root, Inc.'

    o_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('O')]
    assert o_attrs[0].value == 'Example, Corp.'


def test_parse_dn_slash_with_escaped():
    """Test parsing slash-notation DN with escaped characters."""
    dn_str = "/CN=Test\\, Root/O=Example\\, Corp./C=US"
    name = parse_dn(dn_str)
    attrs = list(name)
    assert len(attrs) == 3

    cn_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('CN')]
    assert cn_attrs[0].value == 'Test, Root'

    o_attrs = [attr for attr in attrs if attr.oid == _attr_key_to_oid('O')]
    assert o_attrs[0].value == 'Example, Corp.'


def test_parse_dn_invalid():
    with pytest.raises(ValueError):
        parse_dn("/CN=Test/foo")  # missing equals
    with pytest.raises(ValueError):
        parse_dn("CN=Test,XX=Invalid")  # unsupported attribute