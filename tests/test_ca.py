import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Исправляем импорт - функции теперь внутри cli.main, но мы можем тестировать напрямую
from micropki import ca
from micropki.certificates import parse_dn
from micropki.crypto_utils import generate_rsa_key, encrypt_private_key


def test_init_ca_success(tmp_path):
    """Test successful CA initialisation"""
    from micropki.cli import main
    import sys
    from io import StringIO

    # Create passphrase file
    passfile = tmp_path / "pass.txt"
    passfile.write_bytes(b"testpass123\n")

    # Prepare arguments
    out_dir = tmp_path / "pki"
    args = [
        'init',
        '--subject', '/CN=Test CA',
        '--key-type', 'rsa',
        '--key-size', '4096',
        '--passphrase-file', str(passfile),
        '--out-dir', str(out_dir),
        '--validity-days', '365'
    ]

    # Run command
    with patch.object(sys, 'argv', ['micropki'] + args):
        try:
            main()
        except SystemExit as e:
            assert e.code == 0 or e.code is None

    # Verify files created
    assert (out_dir / 'private' / 'ca.key.pem').exists()
    assert (out_dir / 'certs' / 'ca.cert.pem').exists()
    assert (out_dir / 'policy.txt').exists()


def test_parse_dn():
    """Test DN parsing"""
    dn = parse_dn("/CN=Test/O=Example/C=US")
    assert len(list(dn)) == 3


def test_key_generation():
    """Test RSA key generation"""
    key = generate_rsa_key(2048)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_encrypt_private_key():
    """Test private key encryption"""
    key = generate_rsa_key(2048)
    encrypted = encrypt_private_key(key, b"secret")
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in encrypted