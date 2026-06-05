import pytest
import tempfile
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from micropki.database import init_db, insert_certificate, list_certificates
from micropki.serial import generate_serial, serial_to_hex
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key


@pytest.mark.perf
def test_performance_1000_certificates():
    """Performance test: issue 1000 certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        # Create a CA key and cert for signing
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

        start_time = time.time()
        certificates = []

        for i in range(1000):
            # Generate end-entity key
            ee_key = generate_rsa_key(2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"test-{i}")])

            # Generate serial
            serial_int = generate_serial(db_path)
            serial_hex = serial_to_hex(serial_int)

            # Build certificate
            cert = x509.CertificateBuilder() \
                .subject_name(subject) \
                .issuer_name(ca_subj) \
                .public_key(ee_key.public_key()) \
                .serial_number(serial_int) \
                .not_valid_before(now) \
                .not_valid_after(now + timedelta(days=30)) \
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
                .sign(ca_key, hashes.SHA256())

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            # Insert into database
            cert_data = {
                'serial_hex': serial_hex,
                'subject': subject.rfc4514_string(),
                'issuer': ca_subj.rfc4514_string(),
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat(),
                'cert_pem': cert_pem.decode('utf-8'),
                'status': 'valid',
                'created_at': now.isoformat()
            }
            insert_certificate(db_path, cert_data)
            certificates.append(cert_data)

        end_time = time.time()
        duration = end_time - start_time
        certs_per_second = 1000 / duration

        print(f"\nPerformance Results:")
        print(f"  - Issued 1000 certificates in {duration:.2f} seconds")
        print(f"  - Rate: {certs_per_second:.2f} certificates/second")

        # Verify all certificates are in database
        all_certs = list_certificates(db_path)
        assert len(all_certs) == 1000
        assert duration < 60  # Should complete within 60 seconds


@pytest.mark.perf
def test_performance_crl_generation():
    """Performance test: CRL generation with 1000 revoked certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        init_db(db_path)

        # Create CA
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

        # Insert 1000 revoked certificates
        from micropki.database import update_certificate_status

        for i in range(1000):
            serial_int = generate_serial(db_path)
            serial_hex = serial_to_hex(serial_int)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"test-{i}")])

            cert_data = {
                'serial_hex': serial_hex,
                'subject': subject.rfc4514_string(),
                'issuer': ca_subj.rfc4514_string(),
                'not_before': now.isoformat(),
                'not_after': (now + timedelta(days=30)).isoformat(),
                'cert_pem': 'DUMMY',
                'status': 'valid',
                'created_at': now.isoformat()
            }
            insert_certificate(db_path, cert_data)
            update_certificate_status(db_path, serial_hex, 'revoked', 'keyCompromise')

        # Generate CRL
        from micropki.crl import generate_crl

        start_time = time.time()

        ca_cert_path = Path(tmpdir) / 'ca.cert.pem'
        ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        ca_key_path = Path(tmpdir) / 'ca.key.pem'
        ca_key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ca_key_path.write_bytes(ca_key_pem)

        crl_path = Path(tmpdir) / 'crl.pem'

        generate_crl(
            db_path=db_path,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            ca_passphrase=b'',
            next_update_days=7,
            output_path=crl_path,
            ca_subject=ca_subj.rfc4514_string()
        )

        end_time = time.time()
        duration = end_time - start_time

        print(f"\nCRL Generation Performance:")
        print(f"  - Generated CRL with 1000 revoked entries in {duration:.2f} seconds")
        assert duration < 30  # Should complete within 30 seconds