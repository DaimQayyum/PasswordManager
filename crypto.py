import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import base64

PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32  # 256 bits for AES-256
SALT_SIZE = 16
NONCE_SIZE = 12  # Recommended for GCM


def derive_key(password: str, salt: Optional[bytes] = None, method: str = 'pbkdf2') -> Tuple[bytes, bytes]:
    """Derive a key from the password using PBKDF2. Returns (key, salt)."""
    if salt is None or len(salt) == 0:
        salt = os.urandom(SALT_SIZE)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt


def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-GCM. Returns (ciphertext, nonce, tag)."""
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, nonce, tag


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt ciphertext using AES-GCM. Returns plaintext. Raises InvalidTag if authentication fails."""
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
