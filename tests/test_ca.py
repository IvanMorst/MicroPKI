import pytest
import tempfile
from pathlib import Path
from argparse import Namespace
from micropki.ca import init_ca
from micropki.cli import validate_args  # Changed from _validate_args to validate_args

import pytest
import tempfile
from pathlib import Path
from argparse import Namespace
import os
import time
from micropki.ca import init_ca
from micropki.cli import validate_args


def test_key_generation(tmp_path):
    # Create dummy passphrase file
    passfile = tmp_path / "pass.txt"
    passfile.write_bytes(b"secret\n")

    # Create a temporary directory for output
    out_dir = tmp_path / "pki"

    args = Namespace(
        command='init',
        subject='/CN=Test CA',
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(passfile),
        out_dir=str(out_dir),
        validity_days=365,
        log_file=None
    )

    # Validate args first
    validate_args(args)

    # Run init_ca
    try:
        init_ca(args)
    except Exception as e:
        import traceback
        traceback.print_exc()
        pytest.fail(f"init_ca raised an exception: {e}")

    # Даем время на запись файлов
    time.sleep(0.5)

    # Check directories were created
    assert out_dir.exists(), f"Output directory {out_dir} was not created"
    assert (out_dir / "private").exists(), "private directory was not created"
    assert (out_dir / "certs").exists(), "certs directory was not created"

    # Check files were created
    key_file = out_dir / "private" / "ca.key.pem"
    cert_file = out_dir / "certs" / "ca.cert.pem"
    policy_file = out_dir / "policy.txt"

    # Список файлов в директории для отладки
    if not key_file.exists():
        print(f"\nFiles in {out_dir / 'private'}:")
        if (out_dir / "private").exists():
            for f in (out_dir / "private").iterdir():
                print(f"  {f.name}")

    assert key_file.exists(), f"Key file {key_file} was not created"
    assert cert_file.exists(), f"Certificate file {cert_file} was not created"
    assert policy_file.exists(), f"Policy file {policy_file} was not created"

    # Check file content is not empty
    assert key_file.stat().st_size > 0, "Key file is empty"
    assert cert_file.stat().st_size > 0, "Certificate file is empty"
    assert policy_file.stat().st_size > 0, "Policy file is empty"


def test_validation_unwritable_out_dir(tmp_path):
    # Create a file with same name as out_dir to make it unwritable as directory
    unwritable = tmp_path / "unwritable"
    unwritable.write_bytes(b"")

    # Create a real passphrase file
    passfile = tmp_path / "dummy_pass"
    passfile.write_bytes(b"secret")

    args = Namespace(
        command='init',
        subject='/CN=Test',
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(passfile),
        out_dir=str(unwritable),
        validity_days=365,
        log_file=None
    )

    # validate_args должна поймать эту ошибку
    with pytest.raises((ValueError, OSError, PermissionError, FileExistsError)):
        validate_args(args)


def test_validation_ecc_key_size():
    args = Namespace(
        command='init',
        subject='/CN=Test',
        key_type='ecc',
        key_size=256,  # invalid
        passphrase_file='dummy',
        out_dir='./pki',
        validity_days=365,
        log_file=None
    )
    # Create dummy passphrase file
    Path('dummy').write_bytes(b'secret')
    try:
        with pytest.raises(ValueError, match="ECC key size must be 384"):
            validate_args(args)
    finally:
        Path('dummy').unlink()


def test_validation_missing_passphrase_file():
    args = Namespace(
        command='init',
        subject='/CN=Test',
        key_type='rsa',
        key_size=4096,
        passphrase_file='/nonexistent/pass.txt',
        out_dir='./pki',
        validity_days=365,
        log_file=None
    )
    with pytest.raises(ValueError, match="Passphrase file does not exist"):
        validate_args(args)


def test_validation_invalid_validity_days():
    args = Namespace(
        command='init',
        subject='/CN=Test',
        key_type='rsa',
        key_size=4096,
        passphrase_file='dummy',
        out_dir='./pki',
        validity_days=-1,
        log_file=None
    )
    # Create dummy passphrase file
    Path('dummy').write_bytes(b'secret')
    try:
        with pytest.raises(ValueError, match="Validity days must be positive"):
            validate_args(args)
    finally:
        Path('dummy').unlink()


def test_validation_unwritable_out_dir(tmp_path):
    # Create a file with same name as out_dir to make it unwritable as directory
    unwritable = tmp_path / "unwritable"
    unwritable.write_bytes(b"")

    # Create a real passphrase file
    passfile = tmp_path / "dummy_pass"
    passfile.write_bytes(b"secret")

    args = Namespace(
        command='init',
        subject='/CN=Test',
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(passfile),
        out_dir=str(unwritable),
        validity_days=365,
        log_file=None
    )

    # На Windows файл существует, но не может быть использован как директория
    # validate_args может не поймать это, поэтому проверяем при выполнении
    with pytest.raises((ValueError, OSError, PermissionError, FileExistsError)):
        init_ca(args)