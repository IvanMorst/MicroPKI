import json
import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from threading import Lock

logger = logging.getLogger(__name__)

AUDIT_LEVEL = "AUDIT"

_audit_lock = Lock()
_audit_log_path: Optional[Path] = None
_chain_path: Optional[Path] = None


def init_audit_log(out_dir: Path):
    """Initialise audit log and chain file."""
    global _audit_log_path, _chain_path
    audit_dir = out_dir / 'audit'
    audit_dir.mkdir(parents=True, exist_ok=True)
    _audit_log_path = audit_dir / 'audit.log'
    _chain_path = audit_dir / 'chain.dat'

    if not _audit_log_path.exists():
        # Create first entry with prev_hash = 0
        first_entry = create_audit_entry(
            level=AUDIT_LEVEL,
            operation="audit_init",
            status="success",
            message="Audit log initialised",
            metadata={"path": str(_audit_log_path)},
            prev_hash="0" * 64
        )
        _write_audit_entry(first_entry)


def _get_last_hash() -> str:
    """Read the last hash from chain file."""
    if _chain_path and _chain_path.exists():
        try:
            with open(_chain_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass
    return "0" * 64


def create_audit_entry(level: str, operation: str, status: str, message: str,
                       metadata: Dict[str, Any], prev_hash: str = None) -> Dict[str, Any]:
    """Create an audit log entry as a dictionary."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec='microseconds')

    entry = {
        "timestamp": timestamp,
        "level": level,
        "operation": operation,
        "status": status,
        "message": message,
        "metadata": metadata
    }

    # Calculate hash without the integrity field
    entry_json = json.dumps(entry, sort_keys=True, separators=(',', ':'))
    current_hash = hashlib.sha256(entry_json.encode('utf-8')).hexdigest()

    # Use provided prev_hash or read from chain file
    actual_prev_hash = prev_hash if prev_hash is not None else _get_last_hash()

    entry["integrity"] = {
        "prev_hash": actual_prev_hash,
        "hash": current_hash
    }

    return entry


def _write_audit_entry(entry: Dict[str, Any]):
    """Write a single audit entry to the log file and update chain."""
    with _audit_lock:
        if _audit_log_path:
            with open(_audit_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
                f.flush()
                os.fsync(f.fileno())

        current_hash = entry["integrity"]["hash"]
        if _chain_path:
            with open(_chain_path, 'w', encoding='utf-8') as f:
                f.write(current_hash + '\n')
                f.flush()
                os.fsync(f.fileno())


def log_audit(level: str, operation: str, status: str, message: str, metadata: Dict[str, Any]):
    """Log an audit event."""
    entry = create_audit_entry(level, operation, status, message, metadata)
    _write_audit_entry(entry)
    logger.info(f"[AUDIT] {operation} {status}: {message}")


def verify_audit_log(log_path: Path, chain_path: Path) -> Tuple[bool, List[str]]:
    """Verify the integrity of the audit log."""
    errors = []
    if not log_path.exists():
        return False, ["Audit log file not found"]

    expected_hash = None
    if chain_path.exists():
        with open(chain_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content:
                expected_hash = content

    last_valid_hash = "0" * 64
    line_num = 0

    with open(log_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"Line {line_num}: Invalid JSON - {e}")
                continue

            # Check integrity field exists
            integrity = entry.get("integrity")
            if not integrity:
                errors.append(f"Line {line_num}: Missing integrity field")
                continue

            stored_prev = integrity.get("prev_hash")
            stored_hash = integrity.get("hash")

            # Verify prev_hash matches the previous valid hash
            if stored_prev != last_valid_hash:
                errors.append(
                    f"Line {line_num}: Prev hash mismatch (expected {last_valid_hash[:16]}..., got {stored_prev[:16]}...)")

            # Recompute hash from entry without integrity field
            entry_without_integrity = {k: v for k, v in entry.items() if k != "integrity"}
            entry_json = json.dumps(entry_without_integrity, sort_keys=True, separators=(',', ':'))
            computed_hash = hashlib.sha256(entry_json.encode('utf-8')).hexdigest()

            if computed_hash != stored_hash:
                errors.append(f"Line {line_num}: Hash mismatch (tampering detected)")
            else:
                last_valid_hash = stored_hash

    # After processing all lines, last_valid_hash should be the hash of the last valid entry
    if expected_hash and expected_hash != last_valid_hash:
        errors.append(f"Chain file hash mismatch: expected {expected_hash[:16]}..., got {last_valid_hash[:16]}...")

    return len(errors) == 0, errors


def query_audit_log(log_path: Path, from_time: Optional[str] = None, to_time: Optional[str] = None,
                    level: Optional[str] = None, operation: Optional[str] = None,
                    serial: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query audit log with filters."""
    results = []
    if not log_path.exists():
        return results

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Apply filters
            if from_time and entry.get('timestamp', '') < from_time:
                continue
            if to_time and entry.get('timestamp', '') > to_time:
                continue
            if level and entry.get('level') != level:
                continue
            if operation and entry.get('operation') != operation:
                continue
            if serial:
                metadata = entry.get('metadata', {})
                if metadata.get('serial') != serial:
                    continue

            results.append(entry)

    return results