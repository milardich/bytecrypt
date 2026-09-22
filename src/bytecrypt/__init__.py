"""
bytecrypt: password-based encryption for bytes, files and directories.
"""

from importlib.metadata import PackageNotFoundError, version

from .bytecrypt import (
    MAGIC,
    VERSION_SCRYPT,
    AlreadyEncryptedError,
    BytecryptError,
    FileNameTooLongError,
    InvalidPasswordError,
    NotBytecryptFileError,
    UnsupportedFormatError,
    decrypt_bytes,
    decrypt_directory,
    decrypt_file,
    decrypt_file_name,
    decrypt_string,
    encrypt_bytes,
    encrypt_directory,
    encrypt_file,
    encrypt_file_name,
    encrypt_string,
    looks_encrypted,
    reencrypt_directory,
    reencrypt_file,
)

try:
    __version__ = version("bytecrypt")
except PackageNotFoundError:  # source tree, not installed
    __version__ = "0.0.0+source"


def get_version() -> str:
    return __version__


__all__ = [
    "MAGIC",
    "VERSION_SCRYPT",
    "AlreadyEncryptedError",
    "BytecryptError",
    "FileNameTooLongError",
    "InvalidPasswordError",
    "NotBytecryptFileError",
    "UnsupportedFormatError",
    "decrypt_bytes",
    "decrypt_directory",
    "decrypt_file",
    "decrypt_file_name",
    "decrypt_string",
    "encrypt_bytes",
    "encrypt_directory",
    "encrypt_file",
    "encrypt_file_name",
    "encrypt_string",
    "get_version",
    "looks_encrypted",
    "reencrypt_directory",
    "reencrypt_file",
    "__version__",
]
