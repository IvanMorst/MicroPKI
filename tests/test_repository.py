import pytest
import tempfile
import threading
import time
from pathlib import Path
from http.client import HTTPConnection

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

        # Insert a dummy certificate
        cert_data = {
            'serial_hex': '1234567890ABCDEF',
            'subject': 'CN=Test',
            'issuer': 'CN=TestCA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
            'status': 'valid',
            'created_at': '2025-01-01T00:00:00'
        }
        insert_certificate(db_path, cert_data)

        # Create dummy CA certs
        (cert_dir / 'ca.cert.pem').write_text('FAKE ROOT CERT')
        (cert_dir / 'intermediate.cert.pem').write_text('FAKE INTERMEDIATE CERT')

        # Create dummy CRL
        (crl_dir / 'intermediate.crl.pem').write_text('FAKE CRL')

        # Find a free port
        import socket
        sock = socket.socket()
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()

        server_thread = threading.Thread(
            target=serve_repository,
            args=('127.0.0.1', port, str(db_path), str(cert_dir), str(crl_dir)),
            daemon=True
        )
        server_thread.start()
        time.sleep(0.5)  # Allow server to start

        yield {
            'port': port,
            'db_path': db_path,
            'cert_dir': cert_dir,
            'crl_dir': crl_dir
        }


def test_get_certificate_endpoint(repo_server):
    """Test GET /certificate/<serial> endpoint"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/certificate/1234567890ABCDEF')
    response = conn.getresponse()

    assert response.status == 200
    assert response.getheader('Content-Type') == 'application/x-pem-file'
    data = response.read().decode('utf-8')
    assert 'TEST' in data
    conn.close()


def test_get_certificate_invalid_serial(repo_server):
    """Test GET /certificate/ with invalid serial"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/certificate/INVALID')
    response = conn.getresponse()

    assert response.status == 400
    conn.close()


def test_get_certificate_not_found(repo_server):
    """Test GET /certificate/ with non-existent serial"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/certificate/9999999999999999')
    response = conn.getresponse()

    assert response.status == 404
    conn.close()


def test_get_ca_root_endpoint(repo_server):
    """Test GET /ca/root endpoint"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/ca/root')
    response = conn.getresponse()

    assert response.status == 200
    assert response.getheader('Content-Type') == 'application/x-pem-file'
    data = response.read().decode('utf-8')
    assert 'FAKE ROOT CERT' in data
    conn.close()


def test_get_ca_intermediate_endpoint(repo_server):
    """Test GET /ca/intermediate endpoint"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/ca/intermediate')
    response = conn.getresponse()

    assert response.status == 200
    assert response.getheader('Content-Type') == 'application/x-pem-file'
    data = response.read().decode('utf-8')
    assert 'FAKE INTERMEDIATE CERT' in data
    conn.close()


def test_get_crl_endpoint(repo_server):
    """Test GET /crl endpoint"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl')
    response = conn.getresponse()

    assert response.status == 200
    assert response.getheader('Content-Type') == 'application/pkix-crl'
    conn.close()


def test_404_for_unknown_path(repo_server):
    """Test 404 for unknown endpoint"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/unknown')
    response = conn.getresponse()

    assert response.status == 404
    conn.close()