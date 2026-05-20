import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from .chain import verify_signature

logger = logging.getLogger(__name__)


class ValidationResult:
    """Structured result of certificate path validation."""
    def __init__(self, success: bool, errors: List[str], steps: List[Dict[str, Any]]):
        self.success = success
        self.errors = errors
        self.steps = steps

    def __repr__(self):
        return f"ValidationResult(success={self.success}, errors={self.errors})"


def build_chain(leaf: x509.Certificate, intermediates: List[x509.Certificate],
                roots: List[x509.Certificate]) -> Optional[List[x509.Certificate]]:
    """
    Build certificate chain from leaf to a trusted root.
    Returns list [leaf, intermediate1, ..., root] or None if no chain found.
    """
    possible_issuers = intermediates + roots

    def find_issuer(cert: x509.Certificate, candidates: List[x509.Certificate]) -> Optional[x509.Certificate]:
        for issuer in candidates:
            if cert.issuer == issuer.subject:
                return issuer
        return None

    chain = [leaf]
    current = leaf
    for _ in range(10):
        issuer = find_issuer(current, possible_issuers)
        if issuer is None:
            break
        chain.append(issuer)
        if issuer in roots:
            return chain
        current = issuer
    return None


def validate_certificate(cert: x509.Certificate, issuer: Optional[x509.Certificate] = None,
                         is_ca_expected: bool = False, allowed_ku: Optional[List[str]] = None,
                         path_len_remaining: Optional[int] = None,
                         validation_time: Optional[datetime] = None) -> Tuple[bool, List[str]]:
    """
    Perform basic validation on a single certificate.
    """
    errors = []
    if validation_time is None:
        validation_time = datetime.now(timezone.utc)

    # Validity period - use UTC versions to avoid naive/aware issues
    try:
        # Try UTC attributes first (newer cryptography)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        # Fallback to naive and add timezone
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if validation_time < not_before:
        errors.append(f"Certificate not yet valid (valid from {not_before})")
    if validation_time > not_after:
        errors.append(f"Certificate expired (valid until {not_after})")

    # Signature (if issuer given)
    if issuer is not None:
        from .chain import verify_signature
        if not verify_signature(cert, issuer):
            errors.append("Signature verification failed")

    # BasicConstraints
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bc.value.ca
        if is_ca_expected and not is_ca:
            errors.append("Expected CA certificate but CA=FALSE")
        if not is_ca_expected and is_ca:
            errors.append("Expected end-entity certificate but CA=TRUE")
        if is_ca and path_len_remaining is not None:
            path_len = bc.value.path_length
            if path_len is not None and path_len < path_len_remaining:
                errors.append(f"Path length constraint too low: {path_len} < {path_len_remaining}")
    except x509.ExtensionNotFound:
        if is_ca_expected:
            errors.append("BasicConstraints extension missing for CA certificate")

    # KeyUsage
    if allowed_ku:
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku_map = {
                'digitalSignature': ku.value.digital_signature,
                'keyCertSign': ku.value.key_cert_sign,
                'cRLSign': ku.value.crl_sign,
                'keyEncipherment': ku.value.key_encipherment,
                'dataEncipherment': ku.value.data_encipherment,
                'keyAgreement': ku.value.key_agreement,
            }
            for req in allowed_ku:
                if not ku_map.get(req, False):
                    errors.append(f"Required KeyUsage '{req}' missing")
        except x509.ExtensionNotFound:
            errors.append("KeyUsage extension missing but required")

    return len(errors) == 0, errors
def validate_chain(leaf: x509.Certificate, intermediates: List[x509.Certificate],
                   roots: List[x509.Certificate], validation_time: Optional[datetime] = None,
                   check_revocation: bool = False, revocation_checker=None) -> ValidationResult:
    """
    Full path validation.
    Builds chain, validates each certificate.
    Optionally performs revocation checking.
    """
    steps = []
    errors = []
    chain = build_chain(leaf, intermediates, roots)
    if chain is None:
        errors.append("Could not build certificate chain")
        return ValidationResult(False, errors, steps)

    for i, cert in enumerate(chain):
        issuer = chain[i+1] if i+1 < len(chain) else None
        is_ca_expected = (i != 0)
        allowed_ku = ['keyCertSign'] if is_ca_expected else None
        ok, cert_errors = validate_certificate(cert, issuer, is_ca_expected, allowed_ku, validation_time=validation_time)
        steps.append({
            'certificate': cert.subject.rfc4514_string(),
            'is_ca': is_ca_expected,
            'valid': ok,
            'errors': cert_errors
        })
        if not ok:
            errors.extend(cert_errors)
            return ValidationResult(False, errors, steps)

    if check_revocation and revocation_checker and len(chain) >= 2:
        leaf_cert = chain[0]
        issuer_cert = chain[1]
        try:
            status, details = revocation_checker(leaf_cert, issuer_cert)
            if status != 'good':
                errors.append(f"Revocation status: {status} - {details}")
                return ValidationResult(False, errors, steps)
        except Exception as e:
            errors.append(f"Revocation check failed: {e}")
            return ValidationResult(False, errors, steps)

    return ValidationResult(True, errors, steps)