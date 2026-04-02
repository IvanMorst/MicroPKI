import sqlite3
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL,
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
"""


def init_db(db_path: Path):
    """Create database schema if not exists."""
    # Ensure directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # On Windows, NamedTemporaryFile might have issues, so we use a fixed path in temp
    try:
        conn = sqlite3.connect(str(db_path))
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
        logger.info(f"Database initialised at {db_path}")
    except Exception as e:
        logger.error(f"Failed to initialise database: {e}")
        raise


def get_db_connection(db_path: Path):
    return sqlite3.connect(str(db_path))


def insert_certificate(db_path: Path, cert_data: Dict[str, Any]):
    """Insert a certificate record into the database."""
    conn = get_db_connection(db_path)
    try:
        conn.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cert_data['serial_hex'],
            cert_data['subject'],
            cert_data['issuer'],
            cert_data['not_before'],
            cert_data['not_after'],
            cert_data['cert_pem'],
            cert_data['status'],
            cert_data['created_at']
        ))
        conn.commit()
        logger.info(f"Certificate inserted: serial={cert_data['serial_hex']}, subject={cert_data['subject']}")
    except sqlite3.IntegrityError as e:
        logger.error(f"Duplicate serial number: {cert_data['serial_hex']}")
        raise ValueError(f"Duplicate serial number: {cert_data['serial_hex']}") from e
    except Exception as e:
        logger.error(f"Database insertion failed: {e}")
        raise
    finally:
        conn.close()


def get_certificate_by_serial(db_path: Path, serial_hex: str) -> Optional[Dict[str, Any]]:
    """Retrieve certificate record by serial number (hex string)."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
        row = cursor.fetchone()
        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        return None
    finally:
        conn.close()


def list_certificates(db_path: Path, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """List certificates, optionally filtered by status."""
    conn = get_db_connection(db_path)
    try:
        if status:
            cursor = conn.execute("SELECT * FROM certificates WHERE status = ? ORDER BY id", (status,))
        else:
            cursor = conn.execute("SELECT * FROM certificates ORDER BY id")
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]
    finally:
        conn.close()


def update_certificate_status(db_path: Path, serial_hex: str, status: str, reason: Optional[str] = None):
    """Update status and revocation info (stub for Sprint 4)."""
    conn = get_db_connection(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            UPDATE certificates SET status = ?, revocation_reason = ?, revocation_date = ?
            WHERE serial_hex = ?
        """, (status, reason, now, serial_hex.upper()))
        conn.commit()
        logger.info(f"Certificate {serial_hex} status updated to {status}")
    finally:
        conn.close()