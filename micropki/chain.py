import logging
from datetime import datetime, timezone
from typing import List, Optional
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger(__name__)


def verify_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """
    Verify certificate signature using issuer's public key.
    Handles both RSA and ECDSA signatures.
    """
    try:
        public_key = issuer_cert.public_key()
        signature = cert.signature
        tbs_data = cert.tbs_certificate_bytes

        sig_alg_oid = cert.signature_algorithm_oid
        alg_name = sig_alg_oid._name.lower() if hasattr(sig_alg_oid, '_name') else str(sig_alg_oid)

        if 'rsa' in alg_name:
            if 'sha256' in alg_name:
                hash_algo = hashes.SHA256()
            elif 'sha384' in alg_name:
                hash_algo = hashes.SHA384()
            elif 'sha512' in alg_name:
                hash_algo = hashes.SHA512()
            else:
                hash_algo = hashes.SHA256()
            public_key.verify(signature, tbs_data, padding.PKCS1v15(), hash_algo)
        elif 'ecdsa' in alg_name:
            if 'sha256' in alg_name:
                hash_algo = hashes.SHA256()
            elif 'sha384' in alg_name:
                hash_algo = hashes.SHA384()
            elif 'sha512' in alg_name:
                hash_algo = hashes.SHA512()
            else:
                hash_algo = hashes.SHA256()
            public_key.verify(signature, tbs_data, hash_algo)
        else:
            public_key.verify(signature, tbs_data, padding.PKCS1v15(), hashes.SHA256())

        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def verify_crl_signature(crl: x509.CertificateRevocationList, issuer_cert: x509.Certificate) -> bool:
    """Verify CRL signature using issuer's public key."""
    try:
        issuer_cert.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            crl.signature_algorithm_parameters
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error(f"CRL signature verification error: {e}")
        return False


def validate_chain(
        leaf_cert: x509.Certificate,
        intermediates: List[x509.Certificate],
        root_cert: x509.Certificate
) -> bool:
    """
    Validate a certificate chain.

    Returns True if the chain is valid, False otherwise.
    """
    logger_local = logging.getLogger(__name__)

    if not verify_signature(root_cert, root_cert):
        logger_local.error("Root certificate self-signature verification failed")
        return False

    all_certs = [leaf_cert] + intermediates

    for i in range(len(all_certs) - 1):
        current_cert = all_certs[i]
        issuer_cert = all_certs[i + 1]

        if not verify_signature(current_cert, issuer_cert):
            logger_local.error(f"Certificate at level {i} not properly signed")
            return False

    if intermediates:
        if not verify_signature(intermediates[-1], root_cert):
            logger_local.error("Last intermediate not signed by root")
            return False
    else:
        if not verify_signature(leaf_cert, root_cert):
            logger_local.error("Leaf certificate not signed by root")
            return False

    now = datetime.now(timezone.utc)

    def normalize_datetime(dt):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    for cert in all_certs + [root_cert]:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if now < not_before or now > not_after:
            logger_local.error(f"Certificate is not valid")
            return False

        if cert != leaf_cert:
            try:
                bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if not bc.value.ca:
                    logger_local.error(f"Certificate is not a CA certificate")
                    return False
            except x509.ExtensionNotFound:
                logger_local.error(f"Certificate missing BasicConstraints")
                return False

    return True


def print_chain_info(
        leaf_cert: x509.Certificate,
        intermediates: List[x509.Certificate],
        root_cert: x509.Certificate
):
    """Print human-readable chain information."""
    logger_local = logging.getLogger(__name__)

    logger_local.info("Certificate Chain Validation")
    logger_local.info("=" * 50)
    logger_local.info(f"Leaf Certificate: {leaf_cert.subject.rfc4514_string()}")
    logger_local.info(f"  Serial: {format(leaf_cert.serial_number, 'X')}")
    logger_local.info(f"  Valid: {leaf_cert.not_valid_before} to {leaf_cert.not_valid_after}")

    for i, intermediate in enumerate(intermediates):
        logger_local.info(f"Intermediate {i + 1}: {intermediate.subject.rfc4514_string()}")
        logger_local.info(f"  Serial: {format(intermediate.serial_number, 'X')}")

    logger_local.info(f"Root Certificate: {root_cert.subject.rfc4514_string()}")
    logger_local.info(f"  Serial: {format(root_cert.serial_number, 'X')}")