import os
import time
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def generate_serial(db_path: Optional[Path] = None) -> int:
    """
    Generate a unique 64-bit serial number (max 159 bits per RFC 5280).
    High 40 bits = timestamp (seconds since 2020-01-01), low 24 bits = random.
    This ensures the number is ≤ 159 bits.
    """
    base_epoch = 1577836800  # 2020-01-01 00:00:00 UTC
    now = int(time.time())
    timestamp_part = (now - base_epoch) & 0xFFFFFFFFFF  # 40 bits max
    random_part = int.from_bytes(os.urandom(3), byteorder='big')  # 24 bits
    serial = (timestamp_part << 24) | random_part  # 40+24 = 64 bits

    # Ensure serial is positive and within 159-bit limit
    if serial <= 0:
        serial = int.from_bytes(os.urandom(19), byteorder='big')

    # Check uniqueness if database is provided
    if db_path and db_path.exists():
        from .database import get_certificate_by_serial
        max_attempts = 5
        for attempt in range(max_attempts):
            serial_hex = serial_to_hex(serial)
            existing = get_certificate_by_serial(db_path, serial_hex)
            if existing is None:
                break
            # Generate new serial on collision
            random_part = int.from_bytes(os.urandom(3), byteorder='big')
            serial = (timestamp_part << 24) | random_part
        else:
            raise RuntimeError("Failed to generate unique serial number after multiple attempts")

    return serial


def serial_to_hex(serial: int) -> str:
    return format(serial, 'X')