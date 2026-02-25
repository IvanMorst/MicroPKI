import pytest
from argparse import Namespace
from micropki.ca import init_ca
from micropki.cli import _validate_args

def test_key_generation(tmp_path):
    # Create dummy passphrase file
    passfile = tmp_path / "pass.txt"
    passfile.write_bytes(b"secret\n")

    args = Namespace(
        command='init',
        subject='/CN=Test CA',
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(passfile),
        out_dir=str(tmp_path / "pki"),
        validity_days=365,
        log_file=None
    )
    init_ca(args)
    out = tmp_path / "pki"
    assert (out / "private" / "ca.key.pem").exists()
    assert (out / "certs" / "ca.cert.pem").exists()
    assert (out / "policy.txt").exists()

def test_validation_ecc_key_size():
    args = Namespace(
        command='init',
        key_type='ecc',
        key_size=256  # invalid
    )
    with pytest.raises(ValueError, match="ECC key size must be 384"):
        _validate_args(args)

def test_validation_missing_passphrase_file(tmp_path):
    args = Namespace(
        command='init',
        subject='/CN=Test',
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(tmp_path / "nonexistent.txt"),
        out_dir=str(tmp_path / "pki"),
        validity_days=365,
        log_file=None
    )
    with pytest.raises(ValueError, match="Passphrase file does not exist"):
        _validate_args(args)