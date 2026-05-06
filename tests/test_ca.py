import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from micropki import ca
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key


def test_init_ca_success(tmp_path):
    """Test successful CA initialisation"""
    from micropki.cli import main
    import sys

    # Create passphrase file
    passfile = tmp_path / "pass.txt"
    passfile.write_bytes(b"testpass123\n")

    # Prepare arguments
    out_dir = tmp_path / "pki"
    db_path = out_dir / "micropki.db"

    # First init database
    from micropki.database import init_db
    init_db(db_path)

    args = [
        'init',
        '--subject', '/CN=Test CA',
        '--key-type', 'rsa',
        '--key-size', '4096',
        '--passphrase-file', str(passfile),
        '--out-dir', str(out_dir),
        '--validity-days', '365',
        '--db-path', str(db_path)
    ]

    with patch.object(sys, 'argv', ['micropki'] + args):
        try:
            main()
        except SystemExit as e:
            assert e.code == 0 or e.code is None


def test_parse_dn():
    from micropki.certificates import parse_dn
    name = parse_dn("/CN=Test/O=Example")
    assert name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test"


def test_key_generation():
    rsa_key = generate_rsa_key(4096)
    assert rsa_key.key_size == 4096

    ecc_key = generate_ecc_key()
    assert ecc_key.curve.name == "secp384r1"


def test_encrypt_private_key(tmp_path):
    from micropki.crypto_utils import encrypt_private_key, load_encrypted_private_key
    key = generate_rsa_key(2048)
    passphrase = b"test123"

    encrypted = encrypt_private_key(key, passphrase)
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(encrypted)

    loaded = load_encrypted_private_key(key_path, passphrase)
    assert loaded.key_size == key.key_size