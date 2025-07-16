# gh_runner_service/common/crypto.py
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag

from .exceptions import AppError, CryptographyError


SALT = b'gha-nat-traversal-salt'
ITERATIONS = 480_000

def _derive_key(master_key_hex: str) -> bytes:
    master_key = bytes.fromhex(master_key_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS,
    )
    return kdf.derive(master_key)

def encrypt_payload(payload: str, master_key_hex: str) -> str:
    try:
        encryption_key = _derive_key(master_key_hex)
        payload_bytes = payload.encode('utf-8')
        nonce = os.urandom(12)
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')
    except Exception as e:
        raise AppError(f"Pure Python encryption failed: {e}")

def decrypt_payload(encrypted_payload_b64: str, master_key_hex: str) -> str:
    try:
        encryption_key = _derive_key(master_key_hex)
        encrypted_payload = base64.b64decode(encrypted_payload_b64)
        nonce = encrypted_payload[:12]
        ciphertext = encrypted_payload[12:]
        aesgcm = AESGCM(encryption_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except InvalidTag:
        raise CryptographyError(
            "Decryption failed: Invalid authentication tag. "
            "The key may be incorrect or the payload corrupted."
        )
    except Exception as e:
        raise CryptographyError(f"Pure Python decryption failed: {e}")

