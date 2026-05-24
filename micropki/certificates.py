import os
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def parse_dn(dn_string: str) -> x509.Name:
    """Parse DN in slash or comma format into an x509.Name."""
    if dn_string.startswith('/'):
        # Slash notation: /CN=.../O=.../C=...
        parts = dn_string.split('/')[1:]  # skip leading empty
        attributes = []
        for part in parts:
            if '=' not in part:
                raise ValueError(f"Invalid DN part: {part}")
            key, value = part.split('=', 1)
            oid = _attr_key_to_oid(key.strip())
            attributes.append(x509.NameAttribute(oid, value.strip()))
        return x509.Name(attributes)
    else:
        # Assume RFC 4514 comma-separated
        return x509.Name.from_rfc4514_string(dn_string)

def _attr_key_to_oid(key: str) -> x509.ObjectIdentifier:
    mapping = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'L': NameOID.LOCALITY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'C': NameOID.COUNTRY_NAME,
        'STREET': NameOID.STREET_ADDRESS,
        'DC': NameOID.DOMAIN_COMPONENT,
        'UID': NameOID.USER_ID,
        'EMAIL': NameOID.EMAIL_ADDRESS,
        'E': NameOID.EMAIL_ADDRESS,
    }
    oid = mapping.get(key.upper())
    if oid is None:
        raise ValueError(f"Unsupported DN attribute: {key}")
    return oid


def create_self_signed_cert(
        private_key,
        subject_name: x509.Name,
        validity_days: int,
        key_type: str
) -> x509.Certificate:
    """Generate a self-signed X.509 CA certificate."""
    subject = issuer = subject_name
    # Генерируем 19 байт (152 бита) для гарантии < 159 бит
    serial_bytes = os.urandom(19)
    serial = int.from_bytes(serial_bytes, byteorder='big')

    # Убеждаемся что число положительное и не слишком большое
    if serial.bit_length() >= 159:
        serial = serial >> 1  # Сдвигаем чтобы уменьшить

    now = datetime.now(timezone.utc)
    not_before = now
    not_after = now + timedelta(days=validity_days)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    # Extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    # SubjectKeyIdentifier
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    # AuthorityKeyIdentifier (same as SKI for self-signed)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    # Choose hash algorithm based on key type
    if key_type == 'rsa':
        hash_algo = hashes.SHA256()
    else:  # ecc
        hash_algo = hashes.SHA384()

    cert = builder.sign(private_key=private_key, algorithm=hash_algo)
    return cert