import pytest
import tempfile
from pathlib import Path
from micropki.serial import generate_serial, serial_to_hex
from micropki.database import init_db


def test_generate_serial_no_db():
    serial = generate_serial(db_path=None)
    assert isinstance(serial, int)
    assert serial > 0
    # Check that serial is within 159 bits (RFC 5280 requirement)
    assert serial.bit_length() <= 159
    hex_str = serial_to_hex(serial)
    assert isinstance(hex_str, str)
    assert len(hex_str) <= 40  # 160 bits = 40 hex chars


def test_generate_serial_with_db():
    temp_dir = Path(tempfile.gettempdir()) / "micropki_test"
    temp_dir.mkdir(exist_ok=True)
    db_path = temp_dir / "test_serial.db"

    if db_path.exists():
        db_path.unlink()

    init_db(db_path)

    serial1 = generate_serial(db_path)
    serial2 = generate_serial(db_path)

    assert serial1 != serial2
    assert serial1.bit_length() <= 159
    assert serial2.bit_length() <= 159

    # Cleanup
    if db_path.exists():
        db_path.unlink()


def test_serial_to_hex():
    assert serial_to_hex(255) == 'FF'
    assert serial_to_hex(16) == '10'
    assert serial_to_hex(0) == '0'