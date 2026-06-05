import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID

from micropki.revocation_check import get_ocsp_uri, get_crl_uris
from micropki.crypto_utils import generate_rsa_key


def test_get_ocsp_uri_no_extension():
    """Test OCSP URI extraction when no AIA extension."""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(key, hashes.SHA256())

    uri = get_ocsp_uri(cert)
    assert uri is None


def test_get_crl_uris_no_extension():
    """Test CRL URI extraction when no CDP extension."""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(key, hashes.SHA256())

    uris = get_crl_uris(cert)
    assert uris == []


def test_get_ocsp_uri_with_extension():
    """Test OCSP URI extraction when AIA extension present."""
    key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.now(timezone.utc)

    # Create AIA extension with OCSP URI
    ocsp_uri = "http://ocsp.example.com"
    aia = x509.AuthorityInformationAccess([
        x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.OCSP,
            access_location=x509.UniformResourceIdentifier(ocsp_uri)
        )
    ])

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(aia, critical=False) \
        .sign(key, hashes.SHA256())

    uri = get_ocsp_uri(cert)
    assert uri == ocsp_uri