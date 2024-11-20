from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random
import os
import mimetypes

def generate_salt() -> bytes:
    characters = "AaBbCcDdEeF_fGgHhIiJjKk_LlMmNnOoPpQq_RrSsTt_UuVv_WwXxYyZ-z01_2345-6_789"
    salt = "";
    for i in range(16):
        salt = salt + random.choice(characters)
    return str.encode(salt)


def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
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


def encrypt_directory(path: str, password: bytes | str):
    # dir name to bytes and call encrypt_bytes
    print("encrypting dir")
    pass


def encrypt_file(path: str, password: bytes | str):
    print("\nInfo: Encrypting file " + path)
    if (os.path.isfile(path)):
        f = open(path, "r+b")
        content = f.read()
        encrypted = encrypt_bytes(content, password)
        try:
            f.seek(0)
            f.write(encrypted)
            f.truncate()
            f.close()
            print("Info: encrypted bytes written successfully")
        except IOError as err:
            print("\n" + err)
    else:
        raise TypeError("\n" + path + " is not a file or it doesnt exist.")


def decrypt_file(path: str, password: bytes | str):
    print("\nInfo: Decrypting file " + path)
    if (os.path.isfile(path)):
        f = open(path, "r+b")
        content = f.read()
        decrypted = decrypt_bytes(content, password)
        try:
            f.seek(0)
            f.write(decrypted)
            f.truncate()
            f.close()
            print("Info: decrypted bytes written successfully")
        except IOError as err:
            print("\n" + err)
    else:
        raise TypeError("\n" + path + " is not a file or it doesnt exist.")


def encrypt_string(string: str, password: bytes | str):
    # dir name to bytes and call encrypt_bytes
    print("encrypting string")
    pass