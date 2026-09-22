"""Migration with --reencrypt: legacy to version 1, idempotency, new password.

See FORMAT.md section 7. bytecrypt does not write the plaintext to disk. The
legacy regression vector is the real input for the upgrade.
"""

import json
from pathlib import Path

import pytest

from bytecrypt import (
    MAGIC,
    VERSION_SCRYPT,
    InvalidPasswordError,
    NotBytecryptFileError,
    decrypt_bytes,
    decrypt_file,
    decrypt_string,
    encrypt_bytes,
    reencrypt_file,
)

VECTOR_DIR = Path(__file__).parent / "vectors"


def _legacy_vector():
    manifest = json.loads(
        (VECTOR_DIR / "legacy-v0.3.1.json").read_text(encoding="utf-8")
    )
    blob = (VECTOR_DIR / manifest["file"]).read_bytes()
    return blob, manifest["password_utf8"], bytes.fromhex(
        manifest["plaintext_hex"]
    )


def test_reencrypt_legacy_to_v1(tmp_path):
    blob, password, plaintext = _legacy_vector()
    p = tmp_path / "legacy.bin"
    p.write_bytes(blob)

    assert reencrypt_file(str(p), password) is True
    migrated = p.read_bytes()
    assert migrated[:len(MAGIC)] == MAGIC
    assert migrated[len(MAGIC)] == VERSION_SCRYPT
    assert decrypt_bytes(migrated, password) == plaintext


def test_reencrypt_is_idempotent(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(encrypt_bytes(b"already current", "pw"))
    before = p.read_bytes()

    assert reencrypt_file(str(p), "pw") is False
    assert p.read_bytes() == before


def test_reencrypt_rejects_non_bytecrypt_file(tmp_path):
    # Must raise a typed error, not IndexError from peeking at the version
    # byte of a header that is not there.
    p = tmp_path / "garbage.bin"
    p.write_bytes(MAGIC)
    with pytest.raises(NotBytecryptFileError):
        reencrypt_file(str(p), "pw")


def test_reencrypt_changes_password(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(encrypt_bytes(b"top secret", "old-password"))

    assert reencrypt_file(
        str(p), "old-password", new_password="new-password"
    ) is True

    with pytest.raises(InvalidPasswordError):
        decrypt_file(str(p), "old-password")
    decrypt_file(str(p), "new-password")
    assert p.read_bytes() == b"top secret"


def test_legacy_string_token_still_decrypts():
    # 0.x emitted the raw blob as text, so such a token must still decrypt.
    blob, password, plaintext = _legacy_vector()
    legacy_token = blob.decode("ascii")
    assert decrypt_string(legacy_token, password) == plaintext.decode("utf-8")
