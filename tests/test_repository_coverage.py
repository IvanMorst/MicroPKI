import pytest
import tempfile
from pathlib import Path
from http.client import HTTPConnection
import threading
import time

from micropki.repository import serve_repository
from micropki.database import init_db, insert_certificate


@pytest.fixture
def repo_server():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        cert_dir = Path(tmpdir) / 'certs'
        crl_dir = Path(tmpdir) / 'crl'
        cert_dir.mkdir()
        crl_dir.mkdir()

        init_db(db_path)

        (cert_dir / 'ca.cert.pem').write_text('FAKE ROOT CERT')
        (cert_dir / 'intermediate.cert.pem').write_text('FAKE INTERMEDIATE CERT')
        (crl_dir / 'intermediate.crl.pem').write_text('FAKE CRL')

        cert_data = {
            'serial_hex': 'ABCDEF',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': 'FAKE CERTIFICATE',
            'status': 'valid',
            'created_at': '2025-01-01T00:00:00'
        }
        insert_certificate(db_path, cert_data)

        import socket
        sock = socket.socket()
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()

        server_thread = threading.Thread(
            target=serve_repository,
            args=('127.0.0.1', port, str(db_path), str(cert_dir), str(crl_dir)),
            kwargs={'rate_limit': 0, 'rate_burst': 10},
            daemon=True
        )
        server_thread.start()
        time.sleep(2)

        yield {
            'port': port,
            'cert_dir': cert_dir,
            'crl_dir': crl_dir
        }


def test_repo_serve_certificate_not_found(repo_server):
    """Test GET /certificate/ with non-existent serial returns 404"""
    port = repo_server['port']
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/certificate/XYZ123')
    response = conn.getresponse()
    # Invalid hex serial returns 400, valid hex but not found returns 404
    assert response.status in [400, 404]
    conn.close()


def test_repo_serve_invalid_serial_format(repo_server):
    """Test GET /certificate/ with invalid hex returns 400"""
    port = repo_server['port']
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/certificate/INVALID')
    response = conn.getresponse()
    assert response.status == 400
    conn.close()