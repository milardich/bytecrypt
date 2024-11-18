from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=password,
        iterations=480000
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt_bytes(content: bytes, password: bytes) -> bytes:
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(content)


def decrypt_bytes(content: bytes, password: bytes) -> bytes:
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(content)
