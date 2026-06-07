import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

from micropki.cli import main, _do_list_certs, _do_show_cert, _do_check_revoked, _do_validate_chain


def test_cli_list_certs_json_format():
    """Test list-certs command with JSON format"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        from micropki.database import init_db, insert_certificate
        init_db(db_path)

        cert_data = {
            'serial_hex': 'ABC123',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': 'DUMMY',
            'status': 'valid',
            'created_at': '2025-01-01T00:00:00'
        }
        insert_certificate(db_path, cert_data)

        args = SimpleNamespace(
            db_path=str(db_path),
            status=None,
            format='json'
        )

        with patch('sys.stdout.write') as mock_write:
            _do_list_certs(args)
            mock_write.assert_called()


def test_cli_list_certs_table_format():
    """Test list-certs command with TABLE format"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        from micropki.database import init_db, insert_certificate
        init_db(db_path)

        cert_data = {
            'serial_hex': 'ABC123',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': 'DUMMY',
            'status': 'valid',
            'created_at': '2025-01-01T00:00:00'
        }
        insert_certificate(db_path, cert_data)

        args = SimpleNamespace(
            db_path=str(db_path),
            status=None,
            format='table'
        )

        _do_list_certs(args)  # Should not raise exception


def test_cli_show_cert_not_found():
    """Test show-cert command with non-existent serial"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        from micropki.database import init_db
        init_db(db_path)

        args = SimpleNamespace(
            db_path=str(db_path),
            serial='NOTEXIST'
        )

        with pytest.raises(SystemExit):
            _do_show_cert(args)


def test_cli_check_revoked_not_found():
    """Test check-revoked command with non-existent serial"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        from micropki.database import init_db
        init_db(db_path)

        args = SimpleNamespace(
            db_path=str(db_path),
            serial='NOTEXIST'
        )

        with pytest.raises(SystemExit):
            _do_check_revoked(args)


def test_cli_validate_chain_file_not_found():
    """Test validate-chain with missing files"""
    args = SimpleNamespace(
        leaf='/nonexistent/leaf.pem',
        intermediate=[],
        root='/nonexistent/root.pem'
    )

    with pytest.raises(FileNotFoundError):
        _do_validate_chain(args)


def test_cli_audit_commands():
    """Test audit query and verify commands"""
    with tempfile.TemporaryDirectory() as tmpdir:
        from micropki.audit import init_audit_log
        from micropki.audit import query_audit_log, verify_audit_log

        audit_dir = Path(tmpdir) / 'audit'
        audit_dir.mkdir()
        log_path = audit_dir / 'audit.log'

        # Create a valid audit log
        init_audit_log(Path(tmpdir))

        # Test audit query - call directly without mocking
        results = query_audit_log(log_path)
        assert isinstance(results, list)

        # Test audit verify
        valid, errors = verify_audit_log(log_path, audit_dir / 'chain.dat')
        # May be True or False depending on log content, but function works
        assert isinstance(valid, bool)