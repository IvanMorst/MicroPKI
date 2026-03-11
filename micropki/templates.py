"""Certificate templates for server, client, and code signing certificates."""

from enum import Enum
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from typing import List, Optional, Set
import ipaddress


class TemplateType(Enum):
    SERVER = "server"
    CLIENT = "client"
    CODE_SIGNING = "code_signing"


class Template:
    """Base class for certificate templates."""

    def __init__(self, template_type: TemplateType):
        self.type = template_type

    def get_basic_constraints(self) -> x509.BasicConstraints:
        """Return BasicConstraints extension (CA=FALSE, critical)."""
        return x509.BasicConstraints(ca=False, path_length=None)

    def get_key_usage(self, key_type: str) -> x509.KeyUsage:
        """Return KeyUsage extension based on key type."""
        raise NotImplementedError

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        """Return ExtendedKeyUsage extension."""
        raise NotImplementedError

    def validate_san_types(self, san_entries: List[x509.GeneralName]) -> bool:
        """Validate that SAN types are appropriate for this template."""
        raise NotImplementedError

    def get_allowed_san_types(self) -> Set[str]:
        """Return set of allowed SAN type names."""
        raise NotImplementedError


class ServerTemplate(Template):
    """Server certificate template."""

    def __init__(self):
        super().__init__(TemplateType.SERVER)

    def get_key_usage(self, key_type: str) -> x509.KeyUsage:
        # For RSA: digitalSignature, keyEncipherment
        # For ECC: digitalSignature only
        if key_type == 'rsa':
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        else:  # ECC
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,  # For ECDH
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])

    def get_allowed_san_types(self) -> Set[str]:
        return {'dns', 'ip'}

    def validate_san_types(self, san_entries: List[x509.GeneralName]) -> bool:
        if not san_entries:
            return False

        for entry in san_entries:
            if isinstance(entry, x509.DNSName):
                continue
            elif isinstance(entry, x509.IPAddress):
                continue
            else:
                return False
        return True


class ClientTemplate(Template):
    """Client certificate template."""

    def __init__(self):
        super().__init__(TemplateType.CLIENT)

    def get_key_usage(self, key_type: str) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,  # For ECDH
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

    def get_allowed_san_types(self) -> Set[str]:
        return {'dns', 'email', 'uri'}

    def validate_san_types(self, san_entries: List[x509.GeneralName]) -> bool:
        # Client certs can have any allowed type, but at least one is recommended
        for entry in san_entries:
            if isinstance(entry, x509.DNSName):
                continue
            elif isinstance(entry, x509.RFC822Name):
                continue
            elif isinstance(entry, x509.UniformResourceIdentifier):
                continue
            else:
                return False
        return True  # Empty is allowed but not recommended


class CodeSigningTemplate(Template):
    """Code signing certificate template."""

    def __init__(self):
        super().__init__(TemplateType.CODE_SIGNING)

    def get_key_usage(self, key_type: str) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])

    def get_allowed_san_types(self) -> Set[str]:
        return {'dns', 'uri'}  # IP and email not allowed

    def validate_san_types(self, san_entries: List[x509.GeneralName]) -> bool:
        # Code signing certs typically don't need SANs, but if present,
        # they should be DNS or URI only
        for entry in san_entries:
            if isinstance(entry, x509.DNSName):
                continue
            elif isinstance(entry, x509.UniformResourceIdentifier):
                continue
            else:
                return False
        return True  # Empty is acceptable


def get_template(template_name: str) -> Template:
    """Factory function to get template by name."""
    templates = {
        'server': ServerTemplate,
        'client': ClientTemplate,
        'code_signing': CodeSigningTemplate
    }
    if template_name not in templates:
        raise ValueError(f"Unknown template: {template_name}")
    return templates[template_name]()