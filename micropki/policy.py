import logging
from typing import List, Tuple
from cryptography import x509

logger = logging.getLogger(__name__)

# Policy configuration
MAX_ROOT_VALIDITY_DAYS = 3650
MAX_INTERMEDIATE_VALIDITY_DAYS = 1825
MAX_END_ENTITY_VALIDITY_DAYS = 365

MIN_RSA_KEY_SIZE = {
    'root': 4096,
    'intermediate': 3072,
    'end_entity': 2048
}

MIN_ECC_KEY_SIZE = {
    'root': 384,
    'intermediate': 384,
    'end_entity': 256
}

ALLOWED_SAN_TYPES = {
    'server': ['dns', 'ip'],
    'client': ['dns', 'email', 'uri'],
    'code_signing': ['dns', 'uri']
}

REJECT_WILDCARDS = True


def get_key_size_min(cert_type: str, key_type: str) -> int:
    """Get minimum key size for a given certificate type."""
    if key_type == 'rsa':
        return MIN_RSA_KEY_SIZE.get(cert_type, MIN_RSA_KEY_SIZE['end_entity'])
    else:
        return MIN_ECC_KEY_SIZE.get(cert_type, MIN_ECC_KEY_SIZE['end_entity'])


def validate_key_size(key_size: int, cert_type: str, key_type: str) -> Tuple[bool, str]:
    """Validate key size against policy."""
    min_size = get_key_size_min(cert_type, key_type)
    if key_size < min_size:
        return False, f"Key size {key_size} is less than minimum {min_size} for {cert_type}"
    return True, ""


def validate_validity_days(days: int, cert_type: str) -> Tuple[bool, str]:
    """Validate validity period against policy."""
    max_days = {
        'root': MAX_ROOT_VALIDITY_DAYS,
        'intermediate': MAX_INTERMEDIATE_VALIDITY_DAYS,
        'end_entity': MAX_END_ENTITY_VALIDITY_DAYS
    }.get(cert_type, MAX_END_ENTITY_VALIDITY_DAYS)

    if days > max_days:
        return False, f"Validity {days} days exceeds maximum {max_days} for {cert_type}"
    return True, ""


def validate_san_types(san_entries: List, template_name: str) -> Tuple[bool, str]:
    """Validate SAN types against template policy."""
    allowed = ALLOWED_SAN_TYPES.get(template_name, [])
    for san in san_entries:
        san_type = None
        if isinstance(san, x509.DNSName):
            san_type = 'dns'
            value = san.value
            if REJECT_WILDCARDS and value.startswith('*.'):
                return False, f"Wildcard certificate {value} rejected by policy"
        elif isinstance(san, x509.IPAddress):
            san_type = 'ip'
        elif isinstance(san, x509.RFC822Name):
            san_type = 'email'
        elif isinstance(san, x509.UniformResourceIdentifier):
            san_type = 'uri'

        if san_type not in allowed:
            return False, f"SAN type {san_type} not allowed for template {template_name}"
    return True, ""


def validate_algorithm(signature_algorithm_oid) -> Tuple[bool, str]:
    """Validate signature algorithm."""
    alg_name = signature_algorithm_oid._name
    if 'sha1' in alg_name.lower():
        return False, f"SHA-1 algorithm {alg_name} rejected"
    return True, ""