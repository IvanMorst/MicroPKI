import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki.database import init_db, insert_certificate, update_certificate_status
from micropki.crypto_utils import generate_rsa_key, encrypt_private_key, save_pem, load_encrypted_private_key
from micropki.crl import generate_crl, get_revoked_certificates


@pytest.fixture
def test_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / 'test.db'
        certs_dir = tmp_path / 'certs'
        crl_dir = tmp_path / 'crl'
        private_dir = tmp_path / 'private'

        certs_dir.mkdir()
        crl_dir.mkdir()
        private_dir.mkdir()

        init_db(db_path)

        # Generate CA key and cert
        ca_key = generate_rsa_key(4096)
        ca_pass = b'secret123'
        ca_key_pem = encrypt_private_key(ca_key, ca_pass)
        ca_key_path = private_dir / 'ca.key.pem'
        save_pem(ca_key_pem, ca_key_path, mode=0o600)

        # Create self-signed CA cert
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.now(timezone.utc)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)
        builder = builder.public_key(ca_key.public_key())
        builder = builder.serial_number(1)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=365))

        # Add SKI and AKI for CRL
        ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
        builder = builder.add_extension(ski, critical=False)
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
        builder = builder.add_extension(aki, critical=False)

        ca_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
        ca_cert_path = certs_dir / 'ca.cert.pem'
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        ca_cert_path.write_bytes(ca_cert_pem)

        # Insert a test certificate
        cert_data = {
            'serial_hex': '123456',
            'subject': 'CN=Test Cert',
            'issuer': subject.rfc4514_string(),
            'not_before': now.isoformat(),
            'not_after': (now + timedelta(days=30)).isoformat(),
            'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
            'status': 'valid',
            'created_at': now.isoformat()
        }
        insert_certificate(db_path, cert_data)

        yield {
            'db_path': db_path,
            'ca_cert_path': ca_cert_path,
            'ca_key_path': ca_key_path,
            'ca_passphrase': ca_pass,
            'crl_dir': crl_dir,
            'ca_subject': subject.rfc4514_string()
        }


def test_generate_crl(test_env):
    # Revoke the certificate first
    update_certificate_status(test_env['db_path'], '123456', 'revoked', 'keyCompromise')

    output_path = test_env['crl_dir'] / 'test.crl.pem'

    crl = generate_crl(
        db_path=test_env['db_path'],
        ca_cert_path=test_env['ca_cert_path'],
        ca_key_path=test_env['ca_key_path'],
        ca_passphrase=test_env['ca_passphrase'],
        next_update_days=7,
        output_path=output_path,
        ca_subject=test_env['ca_subject']
    )

    assert output_path.exists()
    assert isinstance(crl, x509.CertificateRevocationList)

    # Verify CRL content
    revoked = list(crl)
    assert len(revoked) == 1
    assert revoked[0].serial_number == 0x123456


def test_get_revoked_certificates(test_env):
    revoked = get_revoked_certificates(test_env['db_path'], test_env['ca_subject'])
    assert len(revoked) == 0

    update_certificate_status(test_env['db_path'], '123456', 'revoked', 'keyCompromise')
    revoked = get_revoked_certificates(test_env['db_path'], test_env['ca_subject'])
    assert len(revoked) == 1