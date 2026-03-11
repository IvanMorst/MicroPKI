"""Certificate chain validation utilities."""

import logging
from datetime import datetime, timezone
from typing import List, Optional
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature

def verify_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Verify certificate signature using issuer's public key."""
    try:
        issuer_public_key = issuer_cert.public_key()

        # Получаем алгоритм подписи из сертификата
        signature_algorithm = cert.signature_algorithm_oid

        # Для RSA ключей
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            # Определяем хеш-алгоритм по OID подписи
            if signature_algorithm.dotted_string == '1.2.840.113549.1.1.11':  # sha256WithRSAEncryption
                hash_algo = hashes.SHA256()
            elif signature_algorithm.dotted_string == '1.2.840.113549.1.1.12':  # sha384WithRSAEncryption
                hash_algo = hashes.SHA384()
            elif signature_algorithm.dotted_string == '1.2.840.113549.1.1.13':  # sha512WithRSAEncryption
                hash_algo = hashes.SHA512()
            else:
                hash_algo = hashes.SHA256()  # По умолчанию

            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algo
            )

        # Для ECC ключей
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            if signature_algorithm.dotted_string == '1.2.840.10045.4.3.2':  # ecdsa-with-SHA256
                hash_algo = hashes.SHA256()
            elif signature_algorithm.dotted_string == '1.2.840.10045.4.3.3':  # ecdsa-with-SHA384
                hash_algo = hashes.SHA384()
            else:
                hash_algo = hashes.SHA256()

            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hash_algo)
            )

        else:
            logging.getLogger(__name__).error(f"Unsupported key type: {type(issuer_public_key)}")
            return False

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        logging.getLogger(__name__).error(f"Signature verification error: {e}")
        return False

def validate_chain(
    leaf_cert: x509.Certificate,
    intermediates: List[x509.Certificate],
    root_cert: x509.Certificate
) -> bool:
    """
    Validate a certificate chain.

    Returns True if the chain is valid, False otherwise.
    A valid chain must have:
    - Root certificate self-signed and valid
    - Each certificate signed by the next one in the chain
    - All certificates within validity period
    - Proper CA flags set
    """
    logger = logging.getLogger(__name__)

    # Проверяем корневой сертификат (самоподписанный)
    if not verify_signature(root_cert, root_cert):
        logger.error("Root certificate self-signature verification failed")
        return False

    # Проверяем все intermediate сертификаты
    all_certs = [leaf_cert] + intermediates

    # Для каждого сертификата (кроме последнего) проверяем подпись следующим
    for i in range(len(all_certs) - 1):
        current_cert = all_certs[i]
        issuer_cert = all_certs[i + 1]

        if not verify_signature(current_cert, issuer_cert):
            logger.error(f"Certificate at level {i} not properly signed")
            return False

    # Если есть intermediate, последний должен быть подписан root
    if intermediates:
        if not verify_signature(intermediates[-1], root_cert):
            logger.error("Last intermediate not signed by root")
            return False
    else:
        # Если нет intermediate, leaf должен быть подписан root
        if not verify_signature(leaf_cert, root_cert):
            logger.error("Leaf certificate not signed by root")
            return False

    # Проверяем все сертификаты на срок действия
    now = datetime.now(timezone.utc)
    for cert in all_certs + [root_cert]:
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            logger.error(f"Certificate {cert.subject.rfc4514_string()} is expired or not yet valid")
            return False

    # Проверяем BasicConstraints
    # Root и intermediate должны быть CA
    for cert in intermediates + [root_cert]:
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if not bc.value.ca:
                logger.error(f"Certificate {cert.subject.rfc4514_string()} is not a CA certificate")
                return False
        except x509.ExtensionNotFound:
            logger.error(f"Certificate {cert.subject.rfc4514_string()} missing BasicConstraints")
            return False

    # Leaf не должен быть CA (опционально)
    try:
        bc = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        if bc.value.ca:
            logger.error("Leaf certificate is a CA certificate")
            return False
    except x509.ExtensionNotFound:
        pass  # Отсутствие BasicConstraints для leaf допустимо

    return True

def print_chain_info(
    leaf_cert: x509.Certificate,
    intermediates: List[x509.Certificate],
    root_cert: x509.Certificate
):
    """Print human-readable chain information."""
    logger = logging.getLogger(__name__)

    logger.info("Certificate Chain Validation")
    logger.info("=" * 50)
    logger.info(f"Leaf Certificate: {leaf_cert.subject.rfc4514_string()}")
    logger.info(f"  Serial: {format(leaf_cert.serial_number, 'X')}")
    logger.info(f"  Valid: {leaf_cert.not_valid_before_utc} to {leaf_cert.not_valid_after_utc}")

    for i, intermediate in enumerate(intermediates):
        logger.info(f"Intermediate {i+1}: {intermediate.subject.rfc4514_string()}")
        logger.info(f"  Serial: {format(intermediate.serial_number, 'X')}")

    logger.info(f"Root Certificate: {root_cert.subject.rfc4514_string()}")
    logger.info(f"  Serial: {format(root_cert.serial_number, 'X')}")