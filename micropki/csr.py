"""CSR generation and handling."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

from . import crypto_utils
from . import templates


def generate_csr(
        private_key: PrivateKeyTypes,
        subject_name: x509.Name,
        is_ca: bool = False,
        pathlen: Optional[int] = None
) -> x509.CertificateSigningRequest:
    """Generate a PKCS#10 Certificate Signing Request."""
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject_name)

    # Add BasicConstraints extension if CA
    if is_ca:
        basic_constraints = x509.BasicConstraints(ca=True, path_length=pathlen)
        builder = builder.add_extension(basic_constraints, critical=True)

    # Build and sign CSR
    csr = builder.sign(private_key, hashes.SHA256())
    return csr


def save_csr(csr: x509.CertificateSigningRequest, path):
    """Save CSR to PEM file."""
    pem_data = csr.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem_data)
    logging.getLogger(__name__).info(f"CSR saved to {path}")


def load_csr(path) -> x509.CertificateSigningRequest:
    """Load CSR from PEM file."""
    pem_data = path.read_bytes()
    return x509.load_pem_x509_csr(pem_data)


def parse_san_string(san_string: str) -> x509.GeneralName:
    """Parse SAN string of format 'type:value' into GeneralName object."""
    if ':' not in san_string:
        raise ValueError(f"Invalid SAN format (missing ':'): {san_string}")

    san_type, value = san_string.split(':', 1)
    san_type = san_type.lower().strip()
    value = value.strip()

    if san_type == 'dns':
        return x509.DNSName(value)
    elif san_type == 'ip':
        try:
            import ipaddress
            ip = ipaddress.ip_address(value)
            return x509.IPAddress(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {value}") from e
    elif san_type == 'email':
        return x509.RFC822Name(value)
    elif san_type == 'uri':
        return x509.UniformResourceIdentifier(value)
    else:
        raise ValueError(f"Unsupported SAN type: {san_type}")