import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

from micropki.cli import main, _validate_init_args, _validate_intermediate_args, _validate_issue_args


@pytest.fixture
def temp_files():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem') as cert, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.key') as key, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.pass') as passfile:
        cert.write("FAKE CERT")
        cert.flush()
        key.write("FAKE KEY")
        key.flush()
        passfile.write("password")
        passfile.flush()
        yield {
            'cert': cert.name,
            'key': key.name,
            'pass': passfile.name
        }


def test_validate_init_args_rsa_size():
    args = SimpleNamespace(key_type='rsa', key_size=2048)
    with pytest.raises(ValueError, match="4096"):
        _validate_init_args(args)


def test_validate_init_args_ecc_size():
    args = SimpleNamespace(key_type='ecc', key_size=256)
    with pytest.raises(ValueError, match="384"):
        _validate_init_args(args)


def test_validate_init_args_valid():
    args = SimpleNamespace(key_type='rsa', key_size=4096, passphrase_file='/tmp/pass', validity_days=365)
    with patch('pathlib.Path.exists', return_value=True):
        _validate_init_args(args)  # Should not raise


def test_validate_intermediate_args_missing_file():
    args = SimpleNamespace(
        key_type='rsa', key_size=4096,
        root_cert='/nonexistent',
        root_key='/tmp/key',
        root_pass_file='/tmp/pass',
        passphrase_file='/tmp/pass',
        validity_days=365
    )
    with pytest.raises(ValueError, match="not found"):
        _validate_intermediate_args(args)


def test_validate_issue_args_missing_file():
    args = SimpleNamespace(
        ca_cert='/nonexistent',
        ca_key='/tmp/key',
        ca_pass_file='/tmp/pass',
        validity_days=365
    )
    with pytest.raises(ValueError, match="not found"):
        _validate_issue_args(args)


def test_cli_revoke():
    test_args = [
        'micropki', 'revoke',
        'ABC123',
        '--reason', 'keyCompromise',
        '--force',
        '--db-path', '/tmp/db.db'
    ]
    with patch.object(sys, 'argv', test_args), \
         patch('micropki.ca.revoke_certificate_cmd') as mock_revoke:
        main()
        mock_revoke.assert_called_once()


def test_cli_gen_crl():
    test_args = [
        'micropki', 'gen-crl',
        '--ca', 'intermediate',
        '--next-update', '14',
        '--out-dir', '/tmp/pki',
        '--passphrase-file', '/tmp/pass'
    ]
    with patch.object(sys, 'argv', test_args), \
         patch('micropki.ca.generate_crl_cmd') as mock_gen:
        main()
        mock_gen.assert_called_once()


def test_cli_list_certs():
    test_args = ['micropki', 'list-certs', '--db-path', '/tmp/db.db']
    with patch.object(sys, 'argv', test_args), \
         patch('micropki.cli._do_list_certs') as mock_list:
        main()
        mock_list.assert_called_once()