"""
Password-based encryption of bytes, strings, files and directories.

The public API, and the only place where crypto happens. FORMAT.md specifies
the on-disk layout normatively, and this module follows it.

bytecrypt writes version 1 only. It keeps reading the legacy 0.x format,
because a file from an old release must stay readable.
"""

import base64
import os
import secrets
import tempfile

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# --- format constants (FORMAT.md) -------------------------------------------

MAGIC = b"\x00BCY"  # leading NUL: a legacy blob can never start with it
VERSION_SCRYPT = 1
_MAGIC_LEN = len(MAGIC)
_HEADER_LEN = _MAGIC_LEN + 1
SALT_LEN = 16
_MIN_LEGACY_LEN = SALT_LEN + 100 # 100 is the shortest Fernet token (empty plaintext), so a headerless input below this length cannot be a legacy blob.
MAX_FILENAME_LEN = 255  # path component limit on most file systems



# --- errors -----------------------------------------------------------------

class BytecryptError(Exception):
    """Base class for all errors raised by bytecrypt."""


class NotBytecryptFileError(BytecryptError):
    """The input is too short, or it is not a known bytecrypt blob."""

    def __init__(self, message="not a bytecrypt-encrypted file"):
        super().__init__(message)


class UnsupportedFormatError(BytecryptError):
    """The blob declares a format version that this bytecrypt does not know."""

    def __init__(self, version=None):
        self.version = version
        msg = "file was created by a newer version of bytecrypt; upgrade it" \
              " (pip install -U bytecrypt)"
        if version is not None:
            msg = "unknown format version 0x%02x: %s" % (version, msg)
        super().__init__(msg)


class InvalidPasswordError(BytecryptError):
    """The authentication failed: wrong password, or a changed file."""

    def __init__(self, message="wrong password or corrupted file"):
        super().__init__(message)


class AlreadyEncryptedError(BytecryptError):
    """bytecrypt refuses to encrypt data that is already a bytecrypt blob."""

    def __init__(self, path=None):
        self.path = path
        target = repr(path) if path is not None else "input"
        super().__init__(
            "%s is already bytecrypt-encrypted (pass force=True / --force to "
            "re-encrypt)" % target)


class FileNameTooLongError(BytecryptError):
    """The encrypted file name is longer than the file system limit."""

    def __init__(self, length):
        self.length = length
        super().__init__(
            "encrypted filename would be %d chars (limit is %d); encrypt the "
            "file without name encryption" % (length, MAX_FILENAME_LEN))



# --- key derivation ---------------------------------------------------------

def _coerce_password(password) -> bytes:
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)


def _derive_key_scrypt(password: bytes, salt: bytes) -> bytes:
    raw = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password)
    return base64.urlsafe_b64encode(raw)


def _derive_key_legacy(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(),
                     length=32,
                     salt=salt,
                     iterations=1000)
    return base64.urlsafe_b64encode(kdf.derive(password))


# Cost parameters come from this table, never from the blob: a crafted header
# must not be able to demand a huge allocation (FORMAT.md 1.2).
_KDF_REGISTRY = {VERSION_SCRYPT: _derive_key_scrypt}



# --- core primitives --------------------------------------------------------

def encrypt_bytes(content: bytes, password) -> bytes:
    """Encrypt ``content`` into a version 1 blob (scrypt + Fernet)."""
    password = _coerce_password(password)
    salt = secrets.token_bytes(SALT_LEN)
    token = Fernet(_derive_key_scrypt(password, salt)).encrypt(content)
    return MAGIC + bytes([VERSION_SCRYPT]) + salt + token


def decrypt_bytes(content: bytes, password) -> bytes:
    """Decrypt a version 1 blob or a legacy blob, dispatching on the magic."""
    password = _coerce_password(password)
    if content[:_MAGIC_LEN] == MAGIC:
        if len(content) < _HEADER_LEN + SALT_LEN:
            raise NotBytecryptFileError()
        version = content[_MAGIC_LEN]
        derive = _KDF_REGISTRY.get(version)
        if derive is None:
            raise UnsupportedFormatError(version)
        salt = content[_HEADER_LEN:_HEADER_LEN + SALT_LEN]
        token = content[_HEADER_LEN + SALT_LEN:]
        key = derive(password, salt)
    elif len(content) >= _MIN_LEGACY_LEN:
        salt = content[:SALT_LEN]
        token = content[SALT_LEN:]
        key = _derive_key_legacy(password, salt)
    else:
        raise NotBytecryptFileError()
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken:
        raise InvalidPasswordError() from None


def looks_encrypted(content: bytes) -> bool:
    """
    True if ``content`` carries the version 1+ magic.
    A legacy blob has no header and looks like arbitrary text, so it can never be detected here (FORMAT.md 4).
    """
    return content[:_MAGIC_LEN] == MAGIC



# --- transportable text encoding (strings and file names) -------------------

# A v1 blob is binary (leading NUL, raw salt), so strings and file names carry it base64-encoded. 
# Decoding also accepts a raw legacy token, which 0.x wrote as text directly.

def _encode_blob(blob: bytes) -> str:
    return base64.urlsafe_b64encode(blob).decode("ascii")


def _decode_token(text: str) -> bytes:
    try:
        candidate = base64.urlsafe_b64decode(text.encode("ascii"))
        if candidate[:_MAGIC_LEN] == MAGIC:
            return candidate
    except (ValueError, UnicodeEncodeError):
        pass
    return text.encode("utf-8")  # legacy: the text is the blob


def encrypt_string(string: str, password) -> str:
    """Encrypt a string and return a transportable base64 token."""
    return _encode_blob(encrypt_bytes(string.encode("utf-8"), password))


def decrypt_string(token: str, password) -> str:
    """Decrypt a token from encrypt_string, or a legacy 0.x token."""
    return decrypt_bytes(_decode_token(token), password).decode("utf-8")



# --- filesystem helpers -----------------------------------------------------

def _atomic_write(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically, so a crash cannot truncate it."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".bctmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def encrypt_file(
    path: str,
    password,
    encrypt_filename=False,
    force=False
) -> str:
    """Encrypt a file in place and return its (possibly renamed) path."""
    with open(path, "rb") as f:
        content = f.read()
    if not force and looks_encrypted(content):
        raise AlreadyEncryptedError(path)
    _atomic_write(path, encrypt_bytes(content, password))
    if encrypt_filename:
        return encrypt_file_name(path, password)
    return path


def decrypt_file(path: str, password, decrypt_filename=False) -> str:
    """
    Decrypt a file in place and return its (possibly renamed) path.
    A wrong password leaves the file untouched: decryption fails before the write.
    """
    with open(path, "rb") as f:
        content = f.read()
    plaintext = decrypt_bytes(content, password)
    _atomic_write(path, plaintext)
    if decrypt_filename:
        return decrypt_file_name(path, password)
    return path


def encrypt_file_name(path: str, password) -> str:
    """Rename a file to its encrypted, base64-encoded name."""
    directory, name = os.path.split(path)
    enc = _encode_blob(encrypt_bytes(name.encode("utf-8"), password))
    if len(enc) > MAX_FILENAME_LEN:
        raise FileNameTooLongError(len(enc))
    new_path = os.path.join(directory, enc)
    os.replace(path, new_path)
    return new_path


def decrypt_file_name(path: str, password) -> str:
    """Reverse encrypt_file_name; also reads a legacy 0.x name."""
    directory, name = os.path.split(path)
    plaintext = decrypt_bytes(_decode_token(name), password).decode("utf-8")
    new_path = os.path.join(directory, plaintext)
    os.replace(path, new_path)
    return new_path



# --- directories ------------------------------------------------------------

def _iter_files(path: str, recursive: bool):
    """
    Yield file paths below ``path``.
    Symbolic links are skipped, so an encryption never escapes the target tree.
    """
    if recursive:
        for root, _dirs, files in os.walk(path, followlinks=False):
            for name in sorted(files):
                full = os.path.join(root, name)
                if not os.path.islink(full):
                    yield full
    else:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full) and not os.path.islink(full):
                yield full


def encrypt_directory(
    path: str,
    password,
    encrypt_filename=False,
    recursive=False,
    force=False
) -> None:
    """
    Encrypt all files in a directory.
    The pre-scan makes the run all-or-nothing: one already-encrypted file must not leave the tree half encrypted.
    """
    files = list(_iter_files(path, recursive))
    if not force:
        for f in files:
            with open(f, "rb") as fh:
                if fh.read(_MAGIC_LEN) == MAGIC:
                    raise AlreadyEncryptedError(f)
    for f in files:
        encrypt_file(f, password, encrypt_filename=encrypt_filename, force=True)


def decrypt_directory(
    path: str,
    password,
    decrypt_filename=False,
    recursive=False
) -> None:
    """Decrypt all files in a directory."""
    for f in list(_iter_files(path, recursive)):
        decrypt_file(f, password, decrypt_filename=decrypt_filename)



# --- migration --------------------------------------------------------------

def reencrypt_file(path: str, password, new_password=None) -> bool:
    """
    Re-encrypt a file in the current format (v0.3.x -> v1.x.x). Return True if it changed.

    Plaintext stays in memory. A file that is already current is skipped
    unless the password changes, which makes an interrupted migration resumable.
    """
    with open(path, "rb") as f:
        content = f.read()
    already_current = (len(content) >= _HEADER_LEN and looks_encrypted(content)
                       and content[_MAGIC_LEN] == VERSION_SCRYPT)
    if already_current and new_password is None:
        return False
    plaintext = decrypt_bytes(content, password)
    target_password = password if new_password is None else new_password
    _atomic_write(path, encrypt_bytes(plaintext, target_password))
    return True


def reencrypt_directory(
    path: str,
    password,
    new_password=None,
    recursive=False
) -> int:
    """Re-encrypt all files in a directory. Return the count of re-encrypts."""
    count = 0
    for f in list(_iter_files(path, recursive)):
        if reencrypt_file(f, password, new_password=new_password):
            count += 1
    return count
