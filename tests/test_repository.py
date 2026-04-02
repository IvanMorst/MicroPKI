import pytest
import tempfile
import threading
import time
import socket
from pathlib import Path
from http.client import HTTPConnection
from micropki.database import init_db, insert_certificate


def find_free_port():
    """Find a free port for testing"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def repo_server():
    """Fixture that starts a repository server for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        cert_dir = Path(tmpdir) / 'certs'
        cert_dir.mkdir()

        # Initialise database
        init_db(db_path)

        # Insert test certificate
        cert_data = {
            'serial_hex': '1234567890ABCDEF',
            'subject': 'CN=Test Certificate',
            'issuer': 'CN=Test CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\nTESTCERT123\n-----END CERTIFICATE-----',
            'status': 'valid',
            'created_at': '2025-01-01T00:00:00'
        }
        insert_certificate(db_path, cert_data)

        # Create dummy CA certificates
        (cert_dir / 'ca.cert.pem').write_text('-----BEGIN CERTIFICATE-----\nROOTCA\n-----END CERTIFICATE-----')
        (cert_dir / 'intermediate.cert.pem').write_text(
            '-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----')

        # Find free port
        port = find_free_port()

        # Import and start server in background thread
        from micropki.repository import serve_repository
        server_thread = threading.Thread(
            target=serve_repository,
            args=('127.0.0.1', port, str(db_path), str(cert_dir)),
            daemon=True
        )
        server_thread.start()

        # Wait for server to start
        time.sleep(1)

        yield {'port': port, 'cert_dir': cert_dir, 'db_path': db_path}


def test_get_certificate_endpoint(repo_server):
    """Test GET /certificate/<serial> endpoint"""
    port = repo_server['port']

    # Test retrieving certificate by serial
    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/certificate/1234567890ABCDEF')
    response = conn.getresponse()

    assert response.status == 200
    data = response.read().decode('utf-8')
    assert 'TESTCERT123' in data
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
    data = response.read().decode('utf-8')
    assert 'ROOTCA' in data
    conn.close()


def test_get_ca_intermediate_endpoint(repo_server):
    """Test GET /ca/intermediate endpoint"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/ca/intermediate')
    response = conn.getresponse()

    assert response.status == 200
    data = response.read().decode('utf-8')
    assert 'INTERMEDIATE' in data
    conn.close()


def test_get_crl_endpoint(repo_server):
    """Test GET /crl endpoint returns 501"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/crl')
    response = conn.getresponse()

    assert response.status == 501
    data = response.read().decode('utf-8')
    assert 'not yet implemented' in data.lower()
    conn.close()


def test_404_for_unknown_path(repo_server):
    """Test 404 for unknown endpoint"""
    port = repo_server['port']

    conn = HTTPConnection(f'127.0.0.1:{port}')
    conn.request('GET', '/unknown')
    response = conn.getresponse()

    assert response.status == 404
    conn.close()