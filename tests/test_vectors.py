"""Regression vectors across versions: proof that old files still decrypt.

For each `tests/vectors/*.json` manifest, this module decrypts the real blob
with the recorded password and compares the expected plaintext. These tests must
pass after the refactor of the format and the KDF. A failure here is a real
backward compatibility regression. See tests/vectors/README.md and FORMAT.md
section 8.

The comparisons use bytes and sha256 only. No test prints decrypted data, thus
the output stays safe on the cp1252 console of Windows, also for a unicode
plaintext.
"""

import glob
import hashlib
import json
import os

import pytest

from bytecrypt import decrypt_bytes

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "vectors")
MANIFESTS = sorted(glob.glob(os.path.join(VECTOR_DIR, "*.json")))


def test_at_least_one_vector_present():
    # A parametrized test that collects nothing would pass silently.
    assert MANIFESTS, "no regression vectors found under tests/vectors/"


@pytest.mark.parametrize(
    "manifest_path", MANIFESTS, ids=[os.path.basename(p) for p in MANIFESTS]
)
def test_vector_decrypts(manifest_path):
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    blob = open(os.path.join(VECTOR_DIR, manifest["file"]), "rb").read()
    assert hashlib.sha256(blob).hexdigest() == manifest["blob_sha256"], (
        "vector .bin has been altered: restore it, do not regenerate"
    )

    plaintext = decrypt_bytes(blob, manifest["password_utf8"].encode("utf-8"))

    assert plaintext == bytes.fromhex(manifest["plaintext_hex"])
    assert hashlib.sha256(plaintext).hexdigest() == manifest["plaintext_sha256"]
