from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random
import os


def generate_salt() -> bytes:
    characters = "AaBbCcDdEeF_fGgHhIiJjKk_LlMmNnOoPpQq_RrSsTt_UuVv_WwXxYyZz01_23456_789"
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


def overwrite_file(file, content):
    try:
        file.seek(0)
        file.write(content)
        file.truncate()
        file.close()
        print("Info: encrypted bytes written successfully")
    except IOError as err:
        print("\n" + err)


def extract_file_name(path: str) -> str:
    if ( len(path.split('/')) <= 0 ):
        return path
    return path.split('/')[-1]


def extract_dir_path(path: str) -> str:
    if ( len(path.split('/')) <= 0 ):
        return path
    dirs = path.split('/')[:-1]
    dir_path = ""
    for i in dirs:
        dir_path = dir_path + i + '/'
    return dir_path


def encrypt_file_name(path: str, password: bytes):
    print("Info: Encrypting file name.")
    file_name = extract_file_name(path)
    e_name = encrypt_bytes(bytes(file_name, encoding="utf-8"), password)
    if (path.__contains__('/')):
        file_dir = extract_dir_path(path)
        os.rename(path, file_dir + e_name.decode("utf-8"))
    else:
        os.rename(path, e_name.decode("utf-8"))


def decrypt_file_name(path: str, password: bytes):
    print("Info: Decrypting file name.")
    file_name = extract_file_name(path)
    d_name = decrypt_bytes(bytes(file_name, encoding="utf-8"), password)
    if (path.__contains__('/')):
        file_dir = extract_dir_path(path)
        os.rename(path, file_dir + d_name.decode("utf-8"))
    else:
        os.rename(path, d_name.decode("utf-8"))


def encrypt_file(path: str, password: bytes | str, encrypt_name=False):
    print("\nInfo: Encrypting file " + path)
    if (os.path.isfile(path)):
        f = open(path, "r+b")
        content = f.read()
        encrypted = encrypt_bytes(content, password)
        overwrite_file(f, encrypted)
        if (encrypt_name):
            encrypt_file_name(path, password)
    else:
        raise TypeError("\n" + path + " is not a file or it doesnt exist.")


def decrypt_file(path: str, password: bytes | str, decrypt_name=False):
    print("\nInfo: Decrypting file " + path)
    if (os.path.isfile(path)):
        f = open(path, "r+b")
        content = f.read()
        decrypted = decrypt_bytes(content, password)
        overwrite_file(f, decrypted)
        if(decrypt_name):
            decrypt_file_name(path, password)
    else:
        raise TypeError("\n" + path + " is not a file or it doesnt exist.")


def encrypt_string(string: str, password: bytes | str):
    encrypted = encrypt_bytes(string.encode("utf-8"), password)
    print("\nUTF-8:\n" + encrypted.decode("utf-8"))
    print("\nHEX:\n" + encrypted.hex())


def decrypt_string(string: str, password: bytes | str):
    decrypted = decrypt_bytes(string.encode("utf-8"), password)
    print("\nUTF-8:\n" + decrypted.decode("utf-8"))
    print("\nHEX:\n" + decrypted.hex())


def encrypt_directory(path: str, password: bytes | str, encrypt_name=False):
    files = os.listdir(path)
    for file in files:
        encrypt_file(path + "/" + file, password, encrypt_name)


def decrypt_directory(path: str, password: bytes | str, decrypt_name=False):
    files = os.listdir(path)
    for file in files:
        decrypt_file(path + "/" + file, password, decrypt_name)
