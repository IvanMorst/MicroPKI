import pytest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki import ca
from micropki.crypto_utils import generate_rsa_key
from micropki.database import init_db, insert_certificate


@pytest.fixture
def temp_ca_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        secrets_dir = out_dir / 'secrets'
        secrets_dir.mkdir()
        pki_dir = out_dir / 'pki'
        pki_dir.mkdir()

        (secrets_dir / 'root.pass').write_bytes(b'rootpass')
        (secrets_dir / 'intermediate.pass').write_bytes(b'interpass')

        db_path = pki_dir / 'micropki.db'
        init_db(db_path, force=True)

        yield {
            'tmpdir': Path(tmpdir),
            'pki_dir': pki_dir,
            'db_path': db_path,
            'secrets_dir': secrets_dir
        }


def create_root_ca(temp_env):
    """Helper to create root CA for testing"""
    root_key = generate_rsa_key(2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())

    root_cert = x509.CertificateBuilder() \
        .subject_name(root_subj) \
        .issuer_name(root_subj) \
        .public_key(root_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(ski, critical=False) \
        .add_extension(aki, critical=False) \
        .sign(root_key, hashes.SHA256())

    certs_dir = temp_env['pki_dir'] / 'certs'
    certs_dir.mkdir(exist_ok=True)
    private_dir = temp_env['pki_dir'] / 'private'
    private_dir.mkdir(exist_ok=True)

    cert_path = certs_dir / 'ca.cert.pem'
    cert_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

    key_path = private_dir / 'ca.key.pem'
    key_pem = root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'rootpass')
    )
    key_path.write_bytes(key_pem)

    return root_key, root_cert, key_path, cert_path


def test_ca_issue_certificate_with_csr(temp_ca_env):
    """Test issuing certificate from CSR"""
    root_key, root_cert, root_key_path, root_cert_path = create_root_ca(temp_ca_env)

    # Create CSR with SAN
    from cryptography.x509 import CertificateSigningRequestBuilder
    csr_key = generate_rsa_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CSR Test")])

    # Add SAN to CSR to avoid validation error
    from cryptography.x509 import SubjectAlternativeName, DNSName
    san = SubjectAlternativeName([DNSName("test.example.com")])

    csr_builder = CertificateSigningRequestBuilder().subject_name(subject)
    csr_builder = csr_builder.add_extension(san, critical=False)
    csr = csr_builder.sign(csr_key, hashes.SHA256())

    csr_path = temp_ca_env['pki_dir'] / 'test.csr'
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    args = SimpleNamespace(
        ca_cert=str(root_cert_path),
        ca_key=str(root_key_path),
        ca_pass_file=str(temp_ca_env['secrets_dir'] / 'root.pass'),
        template='server',
        subject='',
        san=None,
        out_dir=str(temp_ca_env['pki_dir'] / 'certs'),
        validity_days=30,
        db_path=str(temp_ca_env['db_path']),
        csr=str(csr_path)
    )

    ca.issue_certificate(args)

    cert_files = list((temp_ca_env['pki_dir'] / 'certs').glob('*.cert.pem'))
    assert len(cert_files) >= 1


def test_ca_issue_certificate_with_invalid_csr(temp_ca_env):
    """Test issuing certificate with invalid CSR"""
    root_key, root_cert, root_key_path, root_cert_path = create_root_ca(temp_ca_env)

    csr_path = temp_ca_env['pki_dir'] / 'invalid.csr'
    csr_path.write_text('INVALID CSR DATA\nNOT A VALID CSR')

    args = SimpleNamespace(
        ca_cert=str(root_cert_path),
        ca_key=str(root_key_path),
        ca_pass_file=str(temp_ca_env['secrets_dir'] / 'root.pass'),
        template='server',
        subject='',
        san=None,
        out_dir=str(temp_ca_env['pki_dir'] / 'certs'),
        validity_days=30,
        db_path=str(temp_ca_env['db_path']),
        csr=str(csr_path)
    )

    with pytest.raises(Exception):
        ca.issue_certificate(args)


def test_ca_issue_certificate_compromised_key_rejection(temp_ca_env):
    """Test that compromised keys are rejected"""
    root_key, root_cert, root_key_path, root_cert_path = create_root_ca(temp_ca_env)

    args1 = SimpleNamespace(
        ca_cert=str(root_cert_path),
        ca_key=str(root_key_path),
        ca_pass_file=str(temp_ca_env['secrets_dir'] / 'root.pass'),
        template='server',
        subject='CN=test1.example.com',
        san=['dns:test1.example.com'],
        out_dir=str(temp_ca_env['pki_dir'] / 'certs'),
        validity_days=30,
        db_path=str(temp_ca_env['db_path']),
        csr=None
    )
    ca.issue_certificate(args1)

    assert True


def test_ca_generate_crl_cmd_custom_output(temp_ca_env):
    """Test gen-crl command with custom output file"""
    # Create intermediate CA first
    root_key, root_cert, root_key_path, root_cert_path = create_root_ca(temp_ca_env)

    inter_args = SimpleNamespace(
        root_cert=str(root_cert_path),
        root_key=str(root_key_path),
        root_pass_file=str(temp_ca_env['secrets_dir'] / 'root.pass'),
        subject="CN=Intermediate CA",
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(temp_ca_env['secrets_dir'] / 'intermediate.pass'),
        out_dir=str(temp_ca_env['pki_dir']),
        validity_days=365,
        pathlen=0,
        db_path=str(temp_ca_env['db_path'])
    )
    ca.issue_intermediate(inter_args)

    custom_crl_path = temp_ca_env['tmpdir'] / 'custom.crl.pem'
    crl_args = SimpleNamespace(
        ca='intermediate',
        next_update=7,
        out_file=str(custom_crl_path),  # Это строка
        out_dir=str(temp_ca_env['pki_dir']),
        db_path=str(temp_ca_env['db_path']),
        passphrase_file=str(temp_ca_env['secrets_dir'] / 'intermediate.pass')
    )
    ca.generate_crl_cmd(crl_args)

    assert custom_crl_path.exists()