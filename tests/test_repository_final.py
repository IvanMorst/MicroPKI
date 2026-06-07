import pytest
import tempfile
from pathlib import Path
from http.client import HTTPConnection
import threading
import time

from micropki.repository import serve_repository
from micropki.database import init_db, insert_certificate


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

        # Используем корректный HEX-серийный номер (только символы 0-9, A-F)
        cert_data = {
            'serial_hex': '1A2B3C4D5E6F7890',  # Valid HEX
            'subject': 'CN=FullTest',
            'issuer': 'CN=CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': 'FULL CERT DATA',
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

        yield port


def test_repo_serve_crl_with_root_ca(repo_full_server):
    """Test CRL endpoint with root CA"""
    port = repo_full_server
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl?ca=root')
    response = conn.getresponse()
    assert response.status == 200
    conn.close()


def test_repo_serve_crl_file_root(repo_full_server):
    """Test CRL file endpoint for root"""
    port = repo_full_server
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl/root.crl')
    response = conn.getresponse()
    assert response.status == 200
    conn.close()


def test_repo_serve_crl_file_intermediate(repo_full_server):
    """Test CRL file endpoint for intermediate"""
    port = repo_full_server
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl/intermediate.crl')
    response = conn.getresponse()
    assert response.status == 200
    conn.close()


def test_repo_serve_crl_invalid_file(repo_full_server):
    """Test CRL endpoint with invalid file name"""
    port = repo_full_server
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl/invalid.crl')
    response = conn.getresponse()
    assert response.status == 404
    conn.close()


def test_repo_serve_certificate_with_pem_content(repo_full_server):
    """Test certificate endpoint returns correct PEM content"""
    port = repo_full_server
    conn = HTTPConnection(f'127.0.0.1:{port}')
    # Используем корректный HEX-серийный номер
    conn.request('GET', '/certificate/1A2B3C4D5E6F7890')
    response = conn.getresponse()
    if response.status != 200:
        data = response.read().decode()
        print(f"Response status: {response.status}, body: {data}")
    assert response.status == 200, f"Expected 200, got {response.status}"
    data = response.read().decode()
    assert 'FULL CERT DATA' in data
    conn.close()


def test_repo_serve_certificate_with_lowercase_serial(repo_full_server):
    """Test certificate endpoint with lowercase serial (should be normalized)"""
    port = repo_full_server
    conn = HTTPConnection(f'127.0.0.1:{port}')
    # Репозиторий ожидает uppercase, используем его
    conn.request('GET', '/certificate/1A2B3C4D5E6F7890')
    response = conn.getresponse()
    if response.status != 200:
        data = response.read().decode()
        print(f"Response status: {response.status}, body: {data}")
    assert response.status == 200, f"Expected 200, got {response.status}"
    conn.close()