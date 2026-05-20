import logging
import sys
from pathlib import Path
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
import requests

from . import crypto_utils
from .certificates import parse_dn
from .csr import parse_san_string
from .validation import validate_chain
from .revocation_check import check_revocation_status, get_ocsp_uri, get_crl_uris

logger = logging.getLogger(__name__)


def client_gen_csr(args):
    """Generate private key and CSR."""
    out_key = Path(args.out_key)
    out_csr = Path(args.out_csr)

    if args.key_type == 'rsa':
        key = crypto_utils.generate_rsa_key(args.key_size)
    else:
        key = crypto_utils.generate_ecc_key()

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    out_key.parent.mkdir(parents=True, exist_ok=True)
    out_key.write_bytes(key_pem)
    crypto_utils.save_pem(key_pem, out_key, mode=0o600)
    logger.warning(f"Private key saved UNENCRYPTED to {out_key}")

    subject = parse_dn(args.subject)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    if args.san:
        san_entries = [parse_san_string(s) for s in args.san]
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    out_csr.write_bytes(csr_pem)
    logger.info(f"CSR saved to {out_csr}")


def client_request_cert(args):
    """Submit CSR to CA via repository API."""
    csr_path = Path(args.csr)
    ca_url = args.ca_url.rstrip('/')
    template = args.template
    out_cert = Path(args.out_cert)

    if not csr_path.exists():
        raise FileNotFoundError(f"CSR not found: {csr_path}")

    csr_data = csr_path.read_bytes()
    url = f"{ca_url}/request-cert?template={template}"
    headers = {'Content-Type': 'application/x-pem-file'}
    if hasattr(args, 'api_key') and args.api_key:
        headers['X-API-Key'] = args.api_key

    resp = requests.post(url, data=csr_data, headers=headers, timeout=30)
    if resp.status_code != 201:
        raise Exception(f"CA returned error {resp.status_code}: {resp.text}")

    out_cert.parent.mkdir(parents=True, exist_ok=True)
    out_cert.write_bytes(resp.content)
    logger.info(f"Certificate saved to {out_cert}")


def client_validate(args):
    """Validate certificate chain."""
    cert_path = Path(args.cert)
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate not found: {cert_path}")

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())

    trusted_paths = args.trusted if isinstance(args.trusted, list) else [args.trusted]
    roots = []
    for p in trusted_paths:
        data = Path(p).read_bytes()
        for block in data.split(b'-----END CERTIFICATE-----'):
            if block.strip():
                try:
                    roots.append(x509.load_pem_x509_certificate(block + b'-----END CERTIFICATE-----'))
                except:
                    pass

    intermediates = []
    if args.untrusted:
        for p in args.untrusted:
            data = Path(p).read_bytes()
            for block in data.split(b'-----END CERTIFICATE-----'):
                if block.strip():
                    try:
                        intermediates.append(x509.load_pem_x509_certificate(block + b'-----END CERTIFICATE-----'))
                    except:
                        pass

    validation_time = args.validation_time
    if validation_time:
        from datetime import datetime
        validation_time = datetime.fromisoformat(validation_time)

    def revocation_checker(leaf, issuer):
        return check_revocation_status(leaf, issuer, ocsp_url=args.ocsp_url, crl_url=args.crl_url)

    check_revoc = (args.mode == 'full')
    result = validate_chain(cert, intermediates, roots, validation_time,
                            check_revocation=check_revoc,
                            revocation_checker=revocation_checker if check_revoc else None)

    if result.success:
        print("✓ Validation successful")
    else:
        print("✗ Validation failed")
        for err in result.errors:
            print(f"  - {err}")
    for step in result.steps:
        status = "✓" if step['valid'] else "✗"
        print(f"  {step['certificate']}: {status}")
    sys.exit(0 if result.success else 1)


def client_check_status(args):
    """Check revocation status using OCSP or CRL."""
    cert_path = Path(args.cert)
    ca_cert_path = Path(args.ca_cert)
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate not found: {cert_path}")
    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    issuer = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    ocsp_url = args.ocsp_url if args.ocsp_url else get_ocsp_uri(cert)
    crl_url = args.crl_url if args.crl_url else (get_crl_uris(cert)[0] if get_crl_uris(cert) else None)

    status, detail = check_revocation_status(cert, issuer, ocsp_url, crl_url, prefer_ocsp=True)
    print(f"Status: {status}")
    if detail:
        print(f"Details: {detail}")
    sys.exit(0 if status == 'good' else 1)