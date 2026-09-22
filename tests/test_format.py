"""Behavior of the versioned format.

These tests cover the format detection, the decrypt dispatch, the typed errors
and the rejection of a changed blob. See FORMAT.md sections 3 and 4. They pin
the M2 contract.
"""

import pytest

from bytecrypt import (
    MAGIC,
    VERSION_SCRYPT,
    AlreadyEncryptedError,
    InvalidPasswordError,
    NotBytecryptFileError,
    UnsupportedFormatError,
    decrypt_bytes,
    encrypt_bytes,
    encrypt_directory,
    encrypt_file,
    looks_encrypted,
)

PASSWORD = b"pw-format-tests"
_VERSION_OFFSET = len(MAGIC)
_SALT_OFFSET = len(MAGIC) + 1


def test_future_version_reports_unsupported():
    blob = encrypt_bytes(b"data", PASSWORD)
    future = blob[:_VERSION_OFFSET] + bytes([0x7F]) + blob[_SALT_OFFSET:]
    with pytest.raises(UnsupportedFormatError):
        decrypt_bytes(future, PASSWORD)


def test_short_input_is_not_a_bytecrypt_file():
    with pytest.raises(NotBytecryptFileError):
        decrypt_bytes(b"too short", PASSWORD)


def test_versioned_but_truncated_is_not_a_bytecrypt_file():
    with pytest.raises(NotBytecryptFileError):
        decrypt_bytes(MAGIC + bytes([VERSION_SCRYPT]) + b"\x00" * 5, PASSWORD)


def test_tampered_salt_fails_closed():
    blob = bytearray(encrypt_bytes(b"data", PASSWORD))
    blob[_SALT_OFFSET] ^= 0xFF  # wrong key
    with pytest.raises(InvalidPasswordError):
        decrypt_bytes(bytes(blob), PASSWORD)


def test_tampered_token_fails_closed():
    blob = bytearray(encrypt_bytes(b"data", PASSWORD))
    blob[-1] ^= 0xFF  # HMAC mismatch
    with pytest.raises(InvalidPasswordError):
        decrypt_bytes(bytes(blob), PASSWORD)


def test_looks_encrypted():
    assert looks_encrypted(encrypt_bytes(b"x", PASSWORD))
    assert not looks_encrypted(b"plain text, definitely not encrypted at all")


def test_double_encryption_guard(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"data")
    encrypt_file(str(p), PASSWORD)
    once = p.read_bytes()

    with pytest.raises(AlreadyEncryptedError):
        encrypt_file(str(p), PASSWORD)
    assert p.read_bytes() == once

    encrypt_file(str(p), PASSWORD, force=True)
    assert p.read_bytes() != once


def test_directory_guard_is_all_or_nothing(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"a")
    (tmp_path / "b.txt").write_bytes(b"b")
    encrypt_directory(str(tmp_path), PASSWORD)

    (tmp_path / "c.txt").write_bytes(b"c")
    with pytest.raises(AlreadyEncryptedError):
        encrypt_directory(str(tmp_path), PASSWORD)
    assert (tmp_path / "c.txt").read_bytes() == b"c"  # pre-scan refused first
