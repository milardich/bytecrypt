"""Round trip tests and failure tests for the public bytecrypt API.

All tests run against tmp_path, or against a monkeypatched CWD. No test touches
the real fixtures in tests/, and no test writes outside the temp directory. The
comparisons use bytes, and no test prints decrypted unicode. The assertion
output therefore stays safe on the cp1252 console of Windows.
"""

import os
from pathlib import Path

import pytest

from bytecrypt import (
    MAGIC,
    VERSION_SCRYPT,
    InvalidPasswordError,
    decrypt_bytes,
    decrypt_directory,
    decrypt_file,
    decrypt_string,
    encrypt_bytes,
    encrypt_directory,
    encrypt_file,
    encrypt_string,
)

PASSWORD = b"correct horse battery staple"

PAYLOADS = [
    pytest.param(b"", id="empty"),
    pytest.param(b"hello world", id="ascii"),
    pytest.param("café · 日本語 · \U0001f510".encode("utf-8"), id="utf8"),
    pytest.param(bytes(range(256)), id="all-byte-values"),
    pytest.param(os.urandom(4096), id="random-4k"),
]

# --- bytes ------------------------------------------------------------------


@pytest.mark.parametrize("payload", PAYLOADS)
def test_bytes_roundtrip(payload):
    blob = encrypt_bytes(payload, PASSWORD)
    assert decrypt_bytes(blob, PASSWORD) == payload


def test_bytes_written_as_version_1():
    blob = encrypt_bytes(b"data", PASSWORD)
    assert blob[:len(MAGIC)] == MAGIC
    assert blob[len(MAGIC)] == VERSION_SCRYPT


def test_bytes_salt_is_unique_per_encryption():
    a = encrypt_bytes(b"same plaintext", PASSWORD)
    b = encrypt_bytes(b"same plaintext", PASSWORD)
    assert a != b  # fresh salt and IV every time
    assert decrypt_bytes(a, PASSWORD) == b"same plaintext"
    assert decrypt_bytes(b, PASSWORD) == b"same plaintext"


def test_bytes_accepts_str_password():
    blob = encrypt_bytes(b"data", "pässword")
    assert decrypt_bytes(blob, "pässword") == b"data"


def test_bytes_wrong_password_raises():
    blob = encrypt_bytes(b"secret", PASSWORD)
    with pytest.raises(InvalidPasswordError):
        decrypt_bytes(blob, b"wrong password")


# --- string -----------------------------------------------------------------


def test_string_roundtrip():
    token = encrypt_string("café · secret · \U0001f510", PASSWORD)
    assert isinstance(token, str)
    assert decrypt_string(token, PASSWORD) == "café · secret · \U0001f510"


# --- file -------------------------------------------------------------------


def test_file_roundtrip(tmp_path):
    p = tmp_path / "secret.bin"
    content = os.urandom(2048)
    p.write_bytes(content)

    encrypt_file(str(p), PASSWORD)
    assert p.read_bytes() != content

    decrypt_file(str(p), PASSWORD)
    assert p.read_bytes() == content


def test_file_wrong_password_raises_and_preserves_bytes(tmp_path):
    p = tmp_path / "secret.bin"
    content = b"important data " * 16
    p.write_bytes(content)
    encrypt_file(str(p), PASSWORD)
    ciphertext = p.read_bytes()

    with pytest.raises(InvalidPasswordError):
        decrypt_file(str(p), b"wrong password")

    assert p.read_bytes() == ciphertext  # a failed decrypt must not write


# --- directory --------------------------------------------------------------


def _build_tree(root: Path) -> dict:
    files = {
        root / "a.txt": b"alpha top-level",
        root / "b.bin": bytes(range(50)),
        root / "sub" / "c.txt": b"charlie nested",
        root / "sub" / "deep" / "d.txt": b"delta deeper",
    }
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return files


def test_directory_roundtrip_recursive(tmp_path):
    files = _build_tree(tmp_path)
    encrypt_directory(str(tmp_path), PASSWORD, recursive=True)
    for path, data in files.items():
        assert path.read_bytes() != data
    decrypt_directory(str(tmp_path), PASSWORD, recursive=True)
    for path, data in files.items():
        assert path.read_bytes() == data


def test_directory_non_recursive_skips_subdirs(tmp_path):
    files = _build_tree(tmp_path)
    top = [p for p in files if p.parent == tmp_path]
    nested = [p for p in files if p.parent != tmp_path]

    encrypt_directory(str(tmp_path), PASSWORD, recursive=False)
    for p in top:
        assert p.read_bytes() != files[p]
    for p in nested:
        assert p.read_bytes() == files[p]

    decrypt_directory(str(tmp_path), PASSWORD, recursive=False)
    for p in top:
        assert p.read_bytes() == files[p]


# --- filename encryption ----------------------------------------------------


def test_filename_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    content = b"file with an encryptable name"
    Path("secret.txt").write_bytes(content)

    encrypt_file("secret.txt", PASSWORD, encrypt_filename=True)
    names = os.listdir(".")
    assert names != ["secret.txt"]
    assert len(names) == 1
    enc_name = names[0]

    decrypt_file(enc_name, PASSWORD, decrypt_filename=True)
    assert os.listdir(".") == ["secret.txt"]
    assert Path("secret.txt").read_bytes() == content
