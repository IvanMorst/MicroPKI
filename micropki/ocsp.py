import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseBuilder

from .database import get_certificate_by_serial
from .revocation import RevocationReason

logger = logging.getLogger(__name__)


def compute_issuer_hashes(ca_cert: x509.Certificate) -> Tuple[bytes, bytes]:
    """Compute SHA-1 issuer name hash and issuer key hash for OCSP CertID."""
    name_hash = hashes.Hash(hashes.SHA1())
    name_hash.update(ca_cert.subject.public_bytes())
    issuer_name_hash = name_hash.finalize()

    key_hash = hashes.Hash(hashes.SHA1())
    key_hash.update(ca_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    issuer_key_hash = key_hash.finalize()

    return issuer_name_hash, issuer_key_hash


def build_ocsp_response(
        db_path: Path,
        ca_cert: x509.Certificate,
        responder_cert: x509.Certificate,
        responder_key: PrivateKeyTypes,
        request_data: bytes,
        cache_ttl: int
) -> bytes:
    """
    Parse OCSP request, determine status, build and sign OCSP response.
    Returns DER-encoded OCSP response.
    """
    try:
        # Parse the OCSP request
        ocsp_request = x509.load_der_ocsp_request(request_data)

        # Get the serial number from the first request (OCSP typically has one)
        serial_number = None
        for req in ocsp_request:
            serial_number = req.serial_number
            break

        if serial_number is None:
            return _build_error_response()

        serial_hex = format(serial_number, 'X')
        cert_data = get_certificate_by_serial(db_path, serial_hex)

        # Build the OCSP response
        builder = OCSPResponseBuilder()

        # Add the response first
        if cert_data is None:
            builder = builder.add_response(
                cert_status=OCSPResponseBuilder.UNKNOWN,
                certificate=responder_cert,
                issuer=ca_cert,
                serial_number=serial_number,
                revocation_time=None,
                revocation_reason=None
            )
        elif cert_data['status'] == 'revoked':
            rev_time = cert_data['revocation_date']
            if isinstance(rev_time, str):
                rev_time = datetime.fromisoformat(rev_time)
            reason_str = cert_data['revocation_reason']
            rev_reason = RevocationReason[reason_str.upper().replace('-', '_')].value if reason_str else 0
            builder = builder.add_response(
                cert_status=OCSPResponseBuilder.REVOKED,
                certificate=responder_cert,
                issuer=ca_cert,
                serial_number=serial_number,
                revocation_time=rev_time,
                revocation_reason=rev_reason
            )
        else:
            builder = builder.add_response(
                cert_status=OCSPResponseBuilder.GOOD,
                certificate=responder_cert,
                issuer=ca_cert,
                serial_number=serial_number,
                revocation_time=None,
                revocation_reason=None
            )

        # Then set responder ID and produced time
        builder = builder.responder_id(OCSPResponseBuilder.RESPONDER_ID_HASH, responder_cert)
        builder = builder.produced_at(datetime.now(timezone.utc))

        # Build and sign
        response = builder.sign(responder_key, hashes.SHA256())
        return response.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        logger.error(f"Failed to build OCSP response: {e}")
        return _build_error_response()


def _build_error_response() -> bytes:
    """Build an error OCSP response (DER)."""
    try:
        builder = OCSPResponseBuilder()
        response = builder.build_unsafe(
            certificate_status=OCSPResponseBuilder.INTERNAL_ERROR,
            responder_id=OCSPResponseBuilder.RESPONDER_ID_HASH,
            responder_id_value=None,
            produced_at=datetime.now(timezone.utc),
            responses=[]
        )
        return response.public_bytes(serialization.Encoding.DER)
    except Exception:
        # Minimal DER for malformed request
        return b'\x30\x03\x02\x01\x01'