from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import random

def generate_salt() -> bytes:
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    salt = "";
    for i in range(16):
        salt = salt + random.choice(characters)
    return str.encode(salt)


def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt_bytes(content: bytes, password: bytes) -> bytes:
    salt = generate_salt()
    key = generate_key(password, salt)
    f = Fernet(key)
    return salt + f.encrypt(content)


def decrypt_bytes(content: bytes, password: bytes) -> bytes:
    salt = content[:16]
    encrypted_content = content[16:]
    key = generate_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_content)
