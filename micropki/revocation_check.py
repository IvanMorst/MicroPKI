import logging
import requests
from datetime import datetime, timezone
from typing import Tuple, Optional, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

from .chain import verify_signature, verify_crl_signature

logger = logging.getLogger(__name__)


def get_ocsp_uri(cert: x509.Certificate) -> Optional[str]:
    """Extract OCSP responder URI from AIA extension."""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def get_crl_uris(cert: x509.Certificate) -> List[str]:
    """Extract CRL distribution point URIs from CDP extension."""
    uris = []
    try:
        cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for point in cdp.value:
            for name in point.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    uris.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return uris


def check_ocsp(cert: x509.Certificate, issuer: x509.Certificate, ocsp_url: Optional[str] = None,
               nonce: bool = True) -> Tuple[str, str]:
    """
    Perform OCSP check.
    Returns (status, details). status: 'good', 'revoked', 'unknown', 'error'
    """
    if ocsp_url is None:
        ocsp_url = get_ocsp_uri(cert)
        if ocsp_url is None:
            return 'error', "No OCSP URL found in certificate"

    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA1())
    if nonce:
        import os
        from cryptography.x509.ocsp import OCSPNonce
        nonce_value = os.urandom(16)
        builder = builder.add_extension(OCSPNonce(nonce_value), critical=False)
    request = builder.build()
    request_der = request.public_bytes(serialization.Encoding.DER)

    try:
        response = requests.post(ocsp_url, data=request_der, headers={'Content-Type': 'application/ocsp-request'},
                                 timeout=10)
        if response.status_code != 200:
            return 'error', f"HTTP {response.status_code}"
    except Exception as e:
        return 'error', f"Network error: {e}"

    try:
        from cryptography.x509 import load_der_ocsp_response
        ocsp_resp = load_der_ocsp_response(response.content)
    except Exception as e:
        return 'error', f"Failed to parse OCSP response: {e}"

    if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
        return 'error', f"OCSP response status: {ocsp_resp.response_status}"

    responses = ocsp_resp.responses
    if not responses:
        return 'unknown', "No certificate status in response"

    single = responses[0]
    if single.certificate_status == OCSPResponseStatus.GOOD:
        return 'good', "Certificate is good"
    elif single.certificate_status == OCSPResponseStatus.REVOKED:
        rev_time = single.revocation_time
        reason = single.revocation_reason
        return 'revoked', f"Revoked at {rev_time}, reason: {reason}"
    else:
        return 'unknown', "Certificate status unknown"


def check_crl(cert: x509.Certificate, issuer: x509.Certificate, crl_data: Optional[bytes] = None,
              crl_url: Optional[str] = None) -> Tuple[str, str]:
    """
    Check certificate against CRL.
    Returns (status, details).
    """
    if crl_data is None and crl_url is None:
        uris = get_crl_uris(cert)
        if not uris:
            return 'error', "No CRL distribution point found"
        crl_url = uris[0]

    if crl_data is None:
        try:
            resp = requests.get(crl_url, timeout=10)
            if resp.status_code != 200:
                return 'error', f"Failed to fetch CRL: HTTP {resp.status_code}"
            crl_data = resp.content
        except Exception as e:
            return 'error', f"CRL fetch error: {e}"

    try:
        if crl_data.startswith(b'-----BEGIN'):
            crl = x509.load_pem_x509_crl(crl_data)
        else:
            crl = x509.load_der_x509_crl(crl_data)
    except Exception as e:
        return 'error', f"Failed to parse CRL: {e}"

    if crl.issuer != issuer.subject:
        return 'error', "CRL issuer does not match certificate issuer"

    if not verify_crl_signature(crl, issuer):
        return 'error', "CRL signature invalid"

    now = datetime.now(timezone.utc)
    next_update = crl.next_update
    if next_update.tzinfo is None:
        next_update = next_update.replace(tzinfo=timezone.utc)
    if now > next_update:
        logger.warning(f"CRL is expired (nextUpdate={next_update})")

    serial = cert.serial_number
    for revoked in crl:
        if revoked.serial_number == serial:
            reason = "unspecified"
            try:
                reason_ext = revoked.extensions.get_extension_for_oid(ExtensionOID.CRL_REASON)
                reason = str(reason_ext.value)
            except x509.ExtensionNotFound:
                pass
            return 'revoked', f"Serial {hex(serial)} found in CRL, reason: {reason}"
    return 'good', "Certificate not in CRL"


def check_revocation_status(cert: x509.Certificate, issuer: x509.Certificate,
                            ocsp_url: Optional[str] = None, crl_url: Optional[str] = None,
                            prefer_ocsp: bool = True) -> Tuple[str, str]:
    """
    Check revocation using OCSP first, then fallback to CRL.
    Returns (status, details).
    """
    if prefer_ocsp:
        status, detail = check_ocsp(cert, issuer, ocsp_url)
        if status != 'error':
            return status, detail
        logger.info(f"OCSP failed ({detail}), falling back to CRL")
        return check_crl(cert, issuer, crl_url=crl_url)
    else:
        status, detail = check_crl(cert, issuer, crl_url=crl_url)
        if status != 'error':
            return status, detail
        return check_ocsp(cert, issuer, ocsp_url)