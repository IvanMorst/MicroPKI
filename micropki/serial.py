import os
import time
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def generate_serial(db_path: Optional[Path] = None) -> int:
    """
    Generate a unique 64-bit serial number (max 159 bits as per RFC 5280).
    High 32 bits = timestamp (seconds since 2020-01-01), low 32 bits = random.
    Ensures most significant bit is zero.
    """
    base_epoch = 1577836800  # 2020-01-01 00:00:00 UTC
    now = int(time.time())
    timestamp_part = (now - base_epoch) & 0x7FFFFFFF  # 31 bits, ensure MSB = 0
    random_part = int.from_bytes(os.urandom(4), byteorder='big') & 0x7FFFFFFF
    serial = (timestamp_part << 32) | random_part

    # Ensure serial is positive and MSB is zero
    serial = serial & 0x7FFFFFFFFFFFFFFF  # Clear the highest bit (63rd bit)

    if serial <= 0:
        serial = int.from_bytes(os.urandom(16), byteorder='big') & 0x7FFFFFFFFFFFFFFF

    if db_path:
        from .database import get_certificate_by_serial
        max_attempts = 5
        for attempt in range(max_attempts):
            serial_hex = format(serial, 'X')
            existing = get_certificate_by_serial(db_path, serial_hex)
            if existing is None:
                break
            random_part = int.from_bytes(os.urandom(4), byteorder='big') & 0x7FFFFFFF
            serial = (timestamp_part << 32) | random_part
            serial = serial & 0x7FFFFFFFFFFFFFFF
        else:
            raise RuntimeError("Failed to generate unique serial number after multiple attempts")

    return serial


def serial_to_hex(serial: int) -> str:
    return format(serial, 'X').upper()