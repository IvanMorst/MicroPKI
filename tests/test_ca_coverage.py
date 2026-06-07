import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from micropki import ca
from micropki.crypto_utils import generate_rsa_key
from micropki.database import init_db, get_certificate_by_serial, update_certificate_status, insert_certificate


@pytest.fixture
def temp_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        secrets_dir = out_dir / 'secrets'
        secrets_dir.mkdir()
        pki_dir = out_dir / 'pki'
        pki_dir.mkdir()

        (secrets_dir / 'root.pass').write_bytes(b'rootpass')
        (secrets_dir / 'intermediate.pass').write_bytes(b'interpass')
        (secrets_dir / 'ocsp.pass').write_bytes(b'ocspass')

        db_path = pki_dir / 'micropki.db'
        init_db(db_path, force=True)

        yield {
            'tmpdir': tmpdir,
            'out_dir': out_dir,
            'pki_dir': pki_dir,
            'db_path': db_path,
            'secrets_dir': secrets_dir
        }


def create_test_ca_cert(temp_env):
    ca_key = generate_rsa_key(2048)
    ca_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())

    ca_cert = x509.CertificateBuilder() \
        .subject_name(ca_subj) \
        .issuer_name(ca_subj) \
        .public_key(ca_key.public_key()) \
        .serial_number(1) \
        .not_valid_before(now) \
        .not_valid_after(now + timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True) \
        .add_extension(ski, critical=False) \
        .add_extension(aki, critical=False) \
        .sign(ca_key, hashes.SHA256())

    certs_dir = temp_env['pki_dir'] / 'certs'
    certs_dir.mkdir(exist_ok=True)
    private_dir = temp_env['pki_dir'] / 'private'
    private_dir.mkdir(exist_ok=True)

    ca_cert_path = certs_dir / 'ca.cert.pem'
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    ca_key_path = private_dir / 'ca.key.pem'
    ca_key_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'rootpass')
    )
    ca_key_path.write_bytes(ca_key_pem)

    return ca_key, ca_cert, ca_key_path, ca_cert_path


def test_issue_intermediate(temp_env):
    root_key, root_cert, root_key_path, root_cert_path = create_test_ca_cert(temp_env)

    args = SimpleNamespace(
        root_cert=str(root_cert_path),
        root_key=str(root_key_path),
        root_pass_file=str(temp_env['secrets_dir'] / 'root.pass'),
        subject="CN=Test Intermediate CA",
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(temp_env['secrets_dir'] / 'intermediate.pass'),
        out_dir=str(temp_env['pki_dir']),
        validity_days=365,
        pathlen=0,
        db_path=str(temp_env['db_path'])
    )

    ca.issue_intermediate(args)

    inter_cert_path = temp_env['pki_dir'] / 'certs' / 'intermediate.cert.pem'
    assert inter_cert_path.exists()
    inter_key_path = temp_env['pki_dir'] / 'private' / 'intermediate.key.pem'
    assert inter_key_path.exists()


def test_issue_ocsp_cert(temp_env):
    root_key, root_cert, root_key_path, root_cert_path = create_test_ca_cert(temp_env)

    inter_args = SimpleNamespace(
        root_cert=str(root_cert_path),
        root_key=str(root_key_path),
        root_pass_file=str(temp_env['secrets_dir'] / 'root.pass'),
        subject="CN=Intermediate CA",
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(temp_env['secrets_dir'] / 'intermediate.pass'),
        out_dir=str(temp_env['pki_dir']),
        validity_days=365,
        pathlen=0,
        db_path=str(temp_env['db_path'])
    )
    ca.issue_intermediate(inter_args)

    ocsp_args = SimpleNamespace(
        ca_cert=str(temp_env['pki_dir'] / 'certs' / 'intermediate.cert.pem'),
        ca_key=str(temp_env['pki_dir'] / 'private' / 'intermediate.key.pem'),
        ca_pass_file=str(temp_env['secrets_dir'] / 'intermediate.pass'),
        subject="CN=OCSP Responder",
        key_type='rsa',
        key_size=2048,
        san=['dns:ocsp.example.com'],
        out_dir=str(temp_env['pki_dir'] / 'certs'),
        validity_days=365,
        db_path=str(temp_env['db_path'])
    )

    ca.issue_ocsp_cert(ocsp_args)

    ocsp_cert_path = temp_env['pki_dir'] / 'certs' / 'ocsp.cert.pem'
    assert ocsp_cert_path.exists()
    ocsp_key_path = temp_env['pki_dir'] / 'certs' / 'ocsp.key.pem'
    assert ocsp_key_path.exists()


def test_revoke_certificate_cmd_success(temp_env):
    root_key, root_cert, root_key_path, root_cert_path = create_test_ca_cert(temp_env)

    from micropki.ca import issue_certificate
    cert_args = SimpleNamespace(
        ca_cert=str(root_cert_path),
        ca_key=str(root_key_path),
        ca_pass_file=str(temp_env['secrets_dir'] / 'root.pass'),
        template='server',
        subject="CN=test.example.com",
        san=['dns:test.example.com'],
        out_dir=str(temp_env['pki_dir'] / 'certs'),
        validity_days=30,
        db_path=str(temp_env['db_path']),
        csr=None
    )
    issue_certificate(cert_args)

    from micropki.database import list_certificates
    certs = list_certificates(temp_env['db_path'])
    test_cert = next((c for c in certs if c['subject'] == "CN=test.example.com"), None)
    assert test_cert is not None
    serial = test_cert['serial_hex']

    revoke_args = SimpleNamespace(
        serial=serial,
        reason='keyCompromise',
        force=True,
        db_path=str(temp_env['db_path'])
    )
    ca.revoke_certificate_cmd(revoke_args)

    revoked_cert = get_certificate_by_serial(temp_env['db_path'], serial)
    assert revoked_cert['status'] == 'revoked'


def test_revoke_certificate_cmd_not_found(temp_env):
    revoke_args = SimpleNamespace(
        serial='NOTEXIST',
        reason='keyCompromise',
        force=True,
        db_path=str(temp_env['db_path'])
    )
    with pytest.raises(ValueError, match="not found"):
        ca.revoke_certificate_cmd(revoke_args)


def test_generate_crl_cmd(temp_env):
    root_key, root_cert, root_key_path, root_cert_path = create_test_ca_cert(temp_env)
    inter_args = SimpleNamespace(
        root_cert=str(root_cert_path),
        root_key=str(root_key_path),
        root_pass_file=str(temp_env['secrets_dir'] / 'root.pass'),
        subject="CN=Intermediate CA",
        key_type='rsa',
        key_size=4096,
        passphrase_file=str(temp_env['secrets_dir'] / 'intermediate.pass'),
        out_dir=str(temp_env['pki_dir']),
        validity_days=365,
        pathlen=0,
        db_path=str(temp_env['db_path'])
    )
    ca.issue_intermediate(inter_args)

    crl_args = SimpleNamespace(
        ca='intermediate',
        next_update=7,
        out_file=None,
        out_dir=str(temp_env['pki_dir']),
        db_path=str(temp_env['db_path']),
        passphrase_file=str(temp_env['secrets_dir'] / 'intermediate.pass')
    )
    ca.generate_crl_cmd(crl_args)

    crl_path = temp_env['pki_dir'] / 'crl' / 'intermediate.crl.pem'
    assert crl_path.exists()