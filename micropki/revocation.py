import logging
from enum import IntEnum
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class RevocationReason(IntEnum):
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


REASON_MAPPING = {
    'unspecified': RevocationReason.UNSPECIFIED,
    'keycompromise': RevocationReason.KEY_COMPROMISE,
    'cacompromise': RevocationReason.CA_COMPROMISE,
    'affiliationchanged': RevocationReason.AFFILIATION_CHANGED,
    'superseded': RevocationReason.SUPERSEDED,
    'cessationofoperation': RevocationReason.CESSATION_OF_OPERATION,
    'certificatehold': RevocationReason.CERTIFICATE_HOLD,
    'removefromcrl': RevocationReason.REMOVE_FROM_CRL,
    'privilegewithdrawn': RevocationReason.PRIVILEGE_WITHDRAWN,
    'aacompromise': RevocationReason.AA_COMPROMISE,
}


def validate_reason(reason: str) -> RevocationReason:
    """Validate and map reason string to RevocationReason enum."""
    reason_lower = reason.lower().replace('_', '').replace('-', '')
    if reason_lower not in REASON_MAPPING:
        valid = ', '.join(REASON_MAPPING.keys())
        raise ValueError(f"Invalid revocation reason: {reason}. Valid reasons: {valid}")
    return REASON_MAPPING[reason_lower]


def revoke_certificate(db_path: Path, serial_hex: str, reason: str, force: bool = False) -> bool:
    """Revoke a certificate in the database."""
    from .database import get_certificate_by_serial, update_certificate_status

    cert = get_certificate_by_serial(db_path, serial_hex)
    if cert is None:
        raise ValueError(f"Certificate with serial {serial_hex} not found")

    if cert['status'] == 'revoked':
        logger.warning(f"Certificate {serial_hex} is already revoked")
        return False

    validate_reason(reason)
    update_certificate_status(db_path, serial_hex, 'revoked', reason)
    logger.info(f"Revoked certificate {serial_hex} with reason: {reason}")
    return True