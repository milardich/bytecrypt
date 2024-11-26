from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from bytecrypt.err_messages import *
import random
import os


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


def encrypt_file_name(path: str, password: bytes):
    print_info("Info: Encrypting file name.")
    file_name = extract_file_name(path)
    e_name = encrypt_bytes(bytes(file_name, encoding="utf-8"), password)
    if (path.__contains__('/')):
        file_dir = extract_dir_path(path)
        os.rename(path, file_dir + e_name.decode("utf-8"))
    else:
        os.rename(path, e_name.decode("utf-8"))


def decrypt_file_name(path: str, password: bytes):
    print_info("Info: Decrypting file name.")
    file_name = extract_file_name(path)
    d_name = decrypt_bytes(bytes(file_name, encoding="utf-8"), password)
    if (path.__contains__('/')):
        file_dir = extract_dir_path(path)
        os.rename(path, file_dir + d_name.decode("utf-8"))
    else:
        os.rename(path, d_name.decode("utf-8"))


def encrypt_file(path: str, password: bytes | str, encrypt_name=False):
    print_info("\nInfo: Encrypting file \'" + path + "\'.")
    if (os.path.isfile(path)):
        f = open(path, "r+b")
        content = f.read()
        encrypted = encrypt_bytes(content, password)
        overwrite_file(f, encrypted)
        if (encrypt_name):
            encrypt_file_name(path, password)
    else:
        print_err("\nError: \'" + path + "\' is not a file or it doesnt exist.")


def decrypt_file(path: str, password: bytes | str, decrypt_name=False):
    print_info("\nInfo: Decrypting file \'" + path + "\'")
    if (os.path.isfile(path)):
        f = open(path, "r+b")
        content = f.read()
        decrypted = decrypt_bytes(content, password)
        overwrite_file(f, decrypted)
        if (decrypt_name):
            decrypt_file_name(path, password)
    else:
        print_err("\nError: \'" + path + "\' is not a file or it doesnt exist.")


def encrypt_string(string: str, password: bytes | str):
    print_info("Info: Encrypting string \'" + string + "\'.")
    encrypted = encrypt_bytes(string.encode("utf-8"), password)
    print("\nUTF-8:\n" + encrypted.decode("utf-8"))
    print("\nHEX:\n" + encrypted.hex())


def decrypt_string(string: str, password: bytes | str):
    print_info("Info: Decrypting string \'" + string + "\'.")
    decrypted = decrypt_bytes(string.encode("utf-8"), password)
    print("\nUTF-8:\n" + decrypted.decode("utf-8"))
    print("\nHEX:\n" + decrypted.hex())


def encrypt_directory(path: str,
                      password: bytes | str,
                      encrypt_name=False,
                      recursive=False):
    print_info("Info: Encrypting directory \'" + path + "\'.")
    if (not recursive):
        _non_recursive_dir_action(encrypt_file, path, password, encrypt_name)
    else:
        _recursive_dir_action(encrypt_directory, encrypt_file, path, password,
                              encrypt_name)


def decrypt_directory(path: str,
                      password: bytes | str,
                      decrypt_name=False,
                      recursive=False):
    print_info("Info: Decrypting directory \'" + path + "\'.")
    if (not recursive):
        _non_recursive_dir_action(decrypt_file, path, password, decrypt_name)
    else:
        _recursive_dir_action(decrypt_directory, decrypt_file, path, password,
                              decrypt_name)


'''
================    UTILS   ================
'''


def generate_salt() -> bytes:
    characters = ("AaBbCcDdEeF_fGgHhIiJjKkLlMmNnOoPpQ"
                  "q_RrSsTt_UuVv_WwXxYyZz01_23456_789")
    salt = ""
    for i in range(16):
        salt = salt + random.choice(characters)
    return str.encode(salt)


def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(),
                     length=32,
                     salt=salt,
                     iterations=1000)
    return base64.urlsafe_b64encode(kdf.derive(password))


def overwrite_file(file, content):
    try:
        file.seek(0)
        file.write(content)
        file.truncate()
        file.close()
        print_info("Info: New file contents written successfully.")
    except IOError as err:
        print("\n" + err)


def extract_file_name(path: str) -> str:
    if (len(path.split('/')) <= 0):
        return path
    return path.split('/')[-1]


def extract_dir_path(path: str) -> str:
    if (len(path.split('/')) <= 0):
        return path
    dirs = path.split('/')[:-1]
    dir_path = ""
    for i in dirs:
        dir_path = dir_path + i + '/'
    return dir_path


# file_action_func -> encrypt_file or decrypt_file function
# name_action      -> encrypt_name or decrypt_name: bool
def _non_recursive_dir_action(file_action_func, path: str,
                              password: bytes | str, name_action: bool):
    dir_elements = os.listdir(path)
    for dir_element in dir_elements:
        dir_element_path = path + '/' + dir_element
        if (os.path.isfile(dir_element_path)):
            file_action_func(dir_element_path, password, name_action)


# file_action_func -> encrypt_file or decrypt_file: function
# dir_action_func  -> encrypt_directory or decrypt_directory: function
# name_action      -> encrypt_name or decrypt_name: bool
def _recursive_dir_action(dir_action_func, file_action_func, path: str,
                          password: bytes | str, name_action: bool):
    dir_elements = os.listdir(path)
    dir_paths = []
    file_paths = []
    for dir_element in dir_elements:
        dir_element_path = path + '/' + dir_element
        if (os.path.isdir(dir_element_path)):
            dir_paths.append(dir_element_path)
        else:
            file_paths.append(dir_element_path)
    if (len(file_paths) > 0):
        for file in file_paths:
            file_action_func(file, password, name_action)
    if (len(dir_paths) > 0):
        for dir in dir_paths:
            dir_action_func(dir, password, name_action, True)
