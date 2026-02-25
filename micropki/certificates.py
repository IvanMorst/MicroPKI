import re
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple
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
            # Unescape any escaped characters
            value = _unescape_dn_value(value.strip())
            attributes.append(x509.NameAttribute(oid, value))
        return x509.Name(attributes)
    else:
        # For comma-separated format, parse manually respecting escaped commas
        attributes = []
        current_key = []
        current_value = []
        in_key = True
        escape = False
        i = 0
        length = len(dn_string)

        while i < length:
            char = dn_string[i]

            if escape:
                # If we're in escape mode, add the character as-is
                if in_key:
                    current_key.append(char)
                else:
                    current_value.append(char)
                escape = False
                i += 1
                continue

            if char == '\\':
                # Start escape sequence
                escape = True
                i += 1
                continue

            if char == '=' and in_key:
                # End of key, start of value
                in_key = False
                i += 1
                continue

            if char == ',' and not in_key:
                # End of attribute, process it
                key = ''.join(current_key).strip()
                value = ''.join(current_value).strip()
                # Unescape any escaped characters in value
                value = _unescape_dn_value(value)
                oid = _attr_key_to_oid(key)
                attributes.append(x509.NameAttribute(oid, value))
                # Reset for next attribute
                current_key = []
                current_value = []
                in_key = True
                i += 1
                continue

            # Normal character
            if in_key:
                current_key.append(char)
            else:
                current_value.append(char)
            i += 1

        # Don't forget the last attribute (if any)
        if current_key or current_value:
            key = ''.join(current_key).strip()
            value = ''.join(current_value).strip()
            # Unescape any escaped characters in value
            value = _unescape_dn_value(value)
            oid = _attr_key_to_oid(key)
            attributes.append(x509.NameAttribute(oid, value))

        return x509.Name(attributes)


def _unescape_dn_value(value: str) -> str:
    """Unescape escaped characters in a DN value."""
    result = []
    escape = False
    for char in value:
        if escape:
            # Add the escaped character as-is (without the backslash)
            result.append(char)
            escape = False
        elif char == '\\':
            escape = True
        else:
            result.append(char)
    # If there's a trailing backslash (unlikely), add it
    if escape:
        result.append('\\')
    return ''.join(result)

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
    # Generate serial number with maximum 159 bits (20 bytes - 1 bit)
    # Using 19 bytes gives 152 bits which is safe
    serial = int.from_bytes(os.urandom(19), byteorder='big')

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
    # BasicConstraints: CA=True, no pathlen constraint
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    # KeyUsage: keyCertSign and cRLSign (digitalSignature optional)
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