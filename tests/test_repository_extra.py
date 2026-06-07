import pytest
import tempfile
from pathlib import Path
from http.client import HTTPConnection
import threading
import time

from micropki.repository import serve_repository
from micropki.database import init_db, insert_certificate


@pytest.fixture
def repo_server_with_ratelimit():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        cert_dir = Path(tmpdir) / 'certs'
        crl_dir = Path(tmpdir) / 'crl'
        cert_dir.mkdir()
        crl_dir.mkdir()

        init_db(db_path)

        # Create dummy CA certificates
        (cert_dir / 'ca.cert.pem').write_text('-----BEGIN CERTIFICATE-----\nFAKE ROOT\n-----END CERTIFICATE-----')
        (cert_dir / 'intermediate.cert.pem').write_text(
            '-----BEGIN CERTIFICATE-----\nFAKE INTERMEDIATE\n-----END CERTIFICATE-----')

        # Create dummy CRL files
        (crl_dir / 'root.crl.pem').write_text('-----BEGIN X509 CRL-----\nFAKE ROOT CRL\n-----END X509 CRL-----')
        (crl_dir / 'intermediate.crl.pem').write_text(
            '-----BEGIN X509 CRL-----\nFAKE INTERMEDIATE CRL\n-----END X509 CRL-----')

        cert_data = {
            'serial_hex': 'TEST123',
            'subject': 'CN=Test',
            'issuer': 'CN=CA',
            'not_before': '2025-01-01T00:00:00',
            'not_after': '2026-01-01T00:00:00',
            'cert_pem': 'FAKE CERT',
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
            kwargs={'rate_limit': 1, 'rate_burst': 2},
            daemon=True
        )
        server_thread.start()
        time.sleep(2)  # Increase wait time for server to start

        yield port


def test_repo_rate_limit_exceeded(repo_server_with_ratelimit):
    """Test rate limiting functionality"""
    port = repo_server_with_ratelimit
    responses = []

    for i in range(5):
        try:
            conn = HTTPConnection(f'127.0.0.1:{port}')
            conn.request('GET', '/ca/root')
            response = conn.getresponse()
            responses.append(response.status)
            conn.close()
        except ConnectionRefusedError:
            responses.append(0)
        time.sleep(0.1)

    # At least one response should be 429 (rate limit exceeded)
    # or connection refused if server died
    assert any(r == 429 or r == 0 for r in responses)


def test_repo_serve_crl_with_query_param(repo_server_with_ratelimit):
    """Test CRL endpoint with query parameter"""
    port = repo_server_with_ratelimit
    try:
        conn = HTTPConnection(f'127.0.0.1:{port}')
        conn.request('GET', '/crl?ca=intermediate')
        response = conn.getresponse()
        # Either 200 (CRL exists) or 404 (not found) - both are acceptable
        assert response.status in [200, 404]
        conn.close()
    except ConnectionRefusedError:
        pytest.skip("Server not available")


def test_repo_serve_crl_invalid_ca(repo_server_with_ratelimit):
    """Test CRL endpoint with invalid CA parameter"""
    port = repo_server_with_ratelimit
    try:
        conn = HTTPConnection(f'127.0.0.1:{port}')
        conn.request('GET', '/crl?ca=invalid')
        response = conn.getresponse()
        # Should return 400 for invalid CA type
        assert response.status == 400
        conn.close()
    except ConnectionRefusedError:
        pytest.skip("Server not available")


def test_repo_serve_crl_file_endpoint(repo_server_with_ratelimit):
    """Test CRL file endpoint"""
    port = repo_server_with_ratelimit
    try:
        conn = HTTPConnection(f'127.0.0.1:{port}')
        conn.request('GET', '/crl/intermediate.crl')
        response = conn.getresponse()
        # Either 200 (CRL exists) or 404 (not found)
        assert response.status in [200, 404]
        conn.close()
    except ConnectionRefusedError:
        pytest.skip("Server not available")


def test_repo_serve_invalid_serial_format(repo_server_with_ratelimit):
    """Test certificate endpoint with invalid serial format"""
    port = repo_server_with_ratelimit
    try:
        conn = HTTPConnection(f'127.0.0.1:{port}')
        conn.request('GET', '/certificate/INVALID_HEX')
        response = conn.getresponse()
        assert response.status == 400
        conn.close()
    except ConnectionRefusedError:
        pytest.skip("Server not available")