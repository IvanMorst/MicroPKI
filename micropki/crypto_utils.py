import os
import logging
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

def generate_rsa_key(key_size: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def generate_ecc_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1)

def encrypt_private_key(key: PrivateKeyTypes, passphrase: bytes) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )

def load_encrypted_private_key(key_path: Path, passphrase: bytes):
    """Load and decrypt an encrypted private key from PEM file."""
    pem_data = key_path.read_bytes()
    return serialization.load_pem_private_key(pem_data, password=passphrase)

def save_pem(data: bytes, path: Path, mode: int = 0o600):
    path.write_bytes(data)
    try:
        os.chmod(path, mode)
    except Exception:
        logging.getLogger(__name__).warning(f"Could not set permissions on {path}")

def load_passphrase(passphrase_file: Path) -> bytes:
    return passphrase_file.read_bytes().strip()