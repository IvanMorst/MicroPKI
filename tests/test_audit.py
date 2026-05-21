import pytest
import tempfile
import json
from pathlib import Path
from micropki.audit import init_audit_log, log_audit, verify_audit_log, create_audit_entry, query_audit_log


def test_audit_log_creation():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        init_audit_log(out_dir)

        log_audit("AUDIT", "test_op", "success", "Test message", {"key": "value"})

        log_path = out_dir / 'audit' / 'audit.log'
        assert log_path.exists()

        content = log_path.read_text()
        assert "test_op" in content
        assert "success" in content


def test_audit_verification():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        init_audit_log(out_dir)

        log_audit("AUDIT", "op1", "success", "First", {"test": 1})
        log_audit("AUDIT", "op2", "success", "Second", {"test": 2})

        log_path = out_dir / 'audit' / 'audit.log'
        chain_path = out_dir / 'audit' / 'chain.dat'

        valid, errors = verify_audit_log(log_path, chain_path)
        assert valid, f"Verification failed with errors: {errors}"
        assert len(errors) == 0

        # Tamper with log
        content = log_path.read_text()
        content = content.replace("success", "FAILED", 1)
        log_path.write_text(content)

        valid, errors = verify_audit_log(log_path, chain_path)
        assert not valid
        assert len(errors) > 0


def test_audit_query():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        init_audit_log(out_dir)

        log_audit("AUDIT", "issue", "success", "First cert", {"serial": "ABC123", "subject": "test"})
        log_audit("AUDIT", "revoke", "success", "Revoked cert", {"serial": "ABC123", "subject": "test"})
        log_audit("INFO", "info_op", "success", "Info message", {})

        log_path = out_dir / 'audit' / 'audit.log'

        # Query by operation - should exclude audit_init
        results = query_audit_log(log_path, operation="issue")
        assert len(results) == 1
        assert results[0]['operation'] == 'issue'

        # Query by level AUDIT - includes audit_init, issue, revoke (3 total)
        results = query_audit_log(log_path, level="AUDIT")
        # audit_init + issue + revoke = 3
        assert len(results) == 3

        # Query by serial
        results = query_audit_log(log_path, serial="ABC123")
        assert len(results) == 2