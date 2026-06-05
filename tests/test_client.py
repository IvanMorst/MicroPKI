import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.client import client_gen_csr, client_request_cert, client_validate, client_check_status
from micropki.crypto_utils import generate_rsa_key


def test_client_gen_csr():
    """Test CSR generation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_key = Path(tmpdir) / 'key.pem'
        out_csr = Path(tmpdir) / 'csr.pem'

        from types import SimpleNamespace
        args = SimpleNamespace(
            subject="/CN=test.example.com",
            key_type='rsa',
            key_size=2048,
            san=['dns:test.example.com'],
            out_key=str(out_key),
            out_csr=str(out_csr)
        )

        client_gen_csr(args)

        assert out_key.exists()
        assert out_csr.exists()


@patch('requests.post')
def test_client_request_cert(mock_post):
    """Test certificate request via API."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csr_path = Path(tmpdir) / 'test.csr'
        csr_path.write_text('-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----')

        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.content = b'-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----'
        mock_post.return_value = mock_response

        from types import SimpleNamespace
        args = SimpleNamespace(
            csr=str(csr_path),
            template='server',
            ca_url='http://localhost:8080',
            api_key=None,
            out_cert=str(Path(tmpdir) / 'cert.pem')
        )

        client_request_cert(args)

        cert_path = Path(tmpdir) / 'cert.pem'
        assert cert_path.exists()


def test_client_validate_missing_cert():
    """Test validation with missing certificate file."""
    from types import SimpleNamespace
    args = SimpleNamespace(
        cert="/nonexistent/path/cert.pem",
        untrusted=[],
        trusted=["./pki/certs/ca.cert.pem"],
        crl_url=None,
        ocsp_url=None,
        mode='chain',
        validation_time=None
    )

    with pytest.raises(FileNotFoundError):
        client_validate(args)


def test_client_check_status_missing_cert():
    """Test check status with missing certificate."""
    from types import SimpleNamespace
    args = SimpleNamespace(
        cert="/nonexistent/path/cert.pem",
        ca_cert="./pki/certs/ca.cert.pem",
        crl_url=None,
        ocsp_url=None
    )

    with pytest.raises(FileNotFoundError):
        client_check_status(args)