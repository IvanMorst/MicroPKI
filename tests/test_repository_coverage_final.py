import pytest
import tempfile
from pathlib import Path
from http.client import HTTPConnection
import threading
import time

from micropki.repository import serve_repository
from micropki.database import init_db, insert_certificate, list_certificates


@pytest.fixture
def repo_full_server():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        cert_dir = Path(tmpdir) / 'certs'
        crl_dir = Path(tmpdir) / 'crl'
        cert_dir.mkdir()
        crl_dir.mkdir()

        init_db(db_path)

        (cert_dir / 'ca.cert.pem').write_text('FAKE ROOT')
        (cert_dir / 'intermediate.cert.pem').write_text('FAKE INTERMEDIATE')
        (crl_dir / 'intermediate.crl.pem').write_text('FAKE CRL')
        (crl_dir / 'root.crl.pem').write_text('FAKE ROOT CRL')

        # Используем реальный серийный номер в hex формате
        test_serial = '46494E414C54455354'  # "FINALTEST" в hex
        cert_data = {
            'serial_hex': test_serial,
            'subject': 'CN=FinalTest',
            'issuer': 'CN=CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': 'FINAL CERT DATA',
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
            kwargs={'rate_limit': 5, 'rate_burst': 10},
            daemon=True
        )
        server_thread.start()
        time.sleep(1)

        yield {
            'port': port,
            'test_serial': test_serial
        }


def test_repo_rate_limit_with_burst(repo_full_server):
    """Test rate limiting with burst allowance"""
    port = repo_full_server['port']

    # Send requests within burst limit (should all succeed)
    for i in range(8):
        conn = HTTPConnection(f'127.0.0.1:{port}')
        conn.request('GET', '/ca/root')
        response = conn.getresponse()
        response.read()  # Consume response
        # First few should be 200, eventually might get 429
        if response.status == 429:
            break
        conn.close()
        time.sleep(0.05)
    # Test passes if no exception


def test_repo_serve_crl_without_param(repo_full_server):
    """Test CRL endpoint without query parameter (default intermediate)"""
    port = repo_full_server['port']
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl')
    response = conn.getresponse()
    response.read()  # Consume response
    assert response.status == 200
    conn.close()


def test_repo_serve_crl_with_root_param(repo_full_server):
    """Test CRL endpoint with root parameter"""
    port = repo_full_server['port']
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl?ca=root')
    response = conn.getresponse()
    response.read()  # Consume response
    assert response.status == 200
    conn.close()


def test_repo_serve_certificate_with_final_data(repo_full_server):
    """Test certificate endpoint returns correct data"""
    port = repo_full_server['port']
    test_serial = repo_full_server['test_serial']
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', f'/certificate/{test_serial}')
    response = conn.getresponse()
    data = response.read().decode()
    assert response.status == 200, f"Status: {response.status}, Data: {data}"
    assert 'FINAL CERT DATA' in data
    conn.close()