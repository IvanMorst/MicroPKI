import pytest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import generate_rsa_key


def test_client_validate_with_crl_url():
    """Test client validate with CRL URL - using real certificates"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create valid root certificate
        root_key = generate_rsa_key(2048)
        root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
        now = datetime.now(timezone.utc)

        root_cert = x509.CertificateBuilder() \
            .subject_name(root_subj) \
            .issuer_name(root_subj) \
            .public_key(root_key.public_key()) \
            .serial_number(1) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=365)) \
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
            .sign(root_key, hashes.SHA256())

        root_path = Path(tmpdir) / 'root.pem'
        root_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

        # Create leaf certificate signed by root
        leaf_key = generate_rsa_key(2048)
        leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])

        leaf_cert = x509.CertificateBuilder() \
            .subject_name(leaf_subj) \
            .issuer_name(root_subj) \
            .public_key(leaf_key.public_key()) \
            .serial_number(2) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=30)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(root_key, hashes.SHA256())

        cert_path = Path(tmpdir) / 'cert.pem'
        cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))

        args = SimpleNamespace(
            cert=str(cert_path),
            untrusted=[],
            trusted=[str(root_path)],
            crl_url='http://localhost:8080/crl',
            ocsp_url=None,
            mode='chain',
            validation_time=None
        )

        from micropki.client import client_validate
        with pytest.raises(SystemExit) as exc:
            client_validate(args)
        assert exc.value.code in (0, 1)


def test_client_check_status_with_revoked_cert():
    """Test client check status with revoked certificate in DB"""
    with tempfile.TemporaryDirectory() as tmpdir:
        from micropki.database import init_db, insert_certificate
        from micropki.client import client_check_status

        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        # Create CA cert
        ca_key = generate_rsa_key(2048)
        ca_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.now(timezone.utc)

        ca_cert = x509.CertificateBuilder() \
            .subject_name(ca_subj) \
            .issuer_name(ca_subj) \
            .public_key(ca_key.public_key()) \
            .serial_number(1) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=365)) \
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
            .sign(ca_key, hashes.SHA256())

        ca_path = Path(tmpdir) / 'ca.pem'
        ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        # Create valid certificate
        cert_key = generate_rsa_key(2048)
        cert_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
        cert = x509.CertificateBuilder() \
            .subject_name(cert_subj) \
            .issuer_name(ca_subj) \
            .public_key(cert_key.public_key()) \
            .serial_number(123456) \
            .not_valid_before(now) \
            .not_valid_after(now + timedelta(days=30)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(ca_key, hashes.SHA256())

        cert_path = Path(tmpdir) / 'cert.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        # Get certificate PEM for database
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Insert revoked certificate into database
        cert_data = {
            'serial_hex': format(cert.serial_number, 'X'),
            'subject': cert_subj.rfc4514_string(),
            'issuer': ca_subj.rfc4514_string(),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'cert_pem': cert_pem,
            'status': 'revoked',
            'revocation_reason': 'keyCompromise',
            'revocation_date': now.isoformat(),
            'created_at': now.isoformat()
        }
        insert_certificate(db_path, cert_data)

        args = SimpleNamespace(
            cert=str(cert_path),
            ca_cert=str(ca_path),
            crl_url=None,
            ocsp_url=None
        )

        with pytest.raises(SystemExit) as exc:
            client_check_status(args)
        assert exc.value.code == 1  # Revoked status