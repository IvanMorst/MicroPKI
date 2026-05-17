import logging
from datetime import datetime, timezone
from typing import List
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

        # Определяем тип ключа и алгоритм подписи
        sig_alg_oid = cert.signature_algorithm_oid

        # Для RSA
        if 'RSA' in str(sig_alg_oid) or 'rsa' in sig_alg_oid._name:
            # Определяем хеш-алгоритм
            if 'sha256' in sig_alg_oid._name:
                hash_algo = hashes.SHA256()
                pad = padding.PKCS1v15()
            elif 'sha384' in sig_alg_oid._name:
                hash_algo = hashes.SHA384()
                pad = padding.PKCS1v15()
            elif 'sha512' in sig_alg_oid._name:
                hash_algo = hashes.SHA512()
                pad = padding.PKCS1v15()
            else:
                hash_algo = hashes.SHA256()
                pad = padding.PKCS1v15()

            public_key.verify(signature, tbs_data, pad, hash_algo)

        # Для ECDSA
        elif 'ecdsa' in sig_alg_oid._name:
            if 'sha256' in sig_alg_oid._name:
                hash_algo = hashes.SHA256()
            elif 'sha384' in sig_alg_oid._name:
                hash_algo = hashes.SHA384()
            elif 'sha512' in sig_alg_oid._name:
                hash_algo = hashes.SHA512()
            else:
                hash_algo = hashes.SHA256()

            public_key.verify(signature, tbs_data, hash_algo)
        else:
            # Попробуем стандартный способ
            from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
            public_key.verify(
                signature,
                tbs_data,
                rsa_padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
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

    # Проверяем корневой сертификат (самоподписанный)
    if not verify_signature(root_cert, root_cert):
        logger_local.error("Root certificate self-signature verification failed")
        return False

    # Проверяем подписи в цепочке (leaf -> intermediates -> root)
    # Сначала проверяем leaf подписан intermediate или root
    if intermediates:
        # Leaf подписан первым intermediate
        if not verify_signature(leaf_cert, intermediates[0]):
            logger_local.error("Leaf certificate not signed by first intermediate")
            return False

        # Проверяем цепочку intermediate
        for i in range(len(intermediates) - 1):
            if not verify_signature(intermediates[i], intermediates[i + 1]):
                logger_local.error(f"Intermediate {i} not signed by intermediate {i + 1}")
                return False

        # Последний intermediate подписан root
        if not verify_signature(intermediates[-1], root_cert):
            logger_local.error("Last intermediate not signed by root")
            return False
    else:
        # Нет intermediate - leaf должен быть подписан root
        if not verify_signature(leaf_cert, root_cert):
            logger_local.error("Leaf certificate not signed by root")
            return False

    # Проверяем срок действия всех сертификатов
    now = datetime.now(timezone.utc)

    def normalize_datetime(dt):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    # Проверяем leaf сертификат
    leaf_not_before = normalize_datetime(leaf_cert.not_valid_before)
    leaf_not_after = normalize_datetime(leaf_cert.not_valid_after)
    if now < leaf_not_before or now > leaf_not_after:
        logger_local.error(f"Leaf certificate {leaf_cert.subject.rfc4514_string()} is not valid")
        return False

    # Проверяем intermediate сертификаты
    for cert in intermediates:
        not_before = normalize_datetime(cert.not_valid_before)
        not_after = normalize_datetime(cert.not_valid_after)
        if now < not_before or now > not_after:
            logger_local.error(f"Intermediate certificate {cert.subject.rfc4514_string()} is not valid")
            return False

        # Проверяем BasicConstraints: должен быть CA
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if not bc.value.ca:
                logger_local.error(f"Intermediate certificate {cert.subject.rfc4514_string()} is not a CA certificate")
                return False
        except x509.ExtensionNotFound:
            logger_local.error(f"Intermediate certificate {cert.subject.rfc4514_string()} missing BasicConstraints")
            return False

    # Проверяем корневой сертификат
    root_not_before = normalize_datetime(root_cert.not_valid_before)
    root_not_after = normalize_datetime(root_cert.not_valid_after)
    if now < root_not_before or now > root_not_after:
        logger_local.error(f"Root certificate {root_cert.subject.rfc4514_string()} is not valid")
        return False

    # Проверяем BasicConstraints для root
    try:
        bc = root_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        if not bc.value.ca:
            logger_local.error(f"Root certificate {root_cert.subject.rfc4514_string()} is not a CA certificate")
            return False
    except x509.ExtensionNotFound:
        logger_local.error(f"Root certificate {root_cert.subject.rfc4514_string()} missing BasicConstraints")
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