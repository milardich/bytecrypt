# Regression vectors

Each `*.bin` file here is a real bytecrypt blob from a specific released version.
Each blob has a `*.json` manifest. The manifest holds the password, the expected
plaintext (UTF-8, hexadecimal and sha256) and the provenance.
`tests/test_vectors.py` decrypts each vector on each supported Python version and
compares the plaintext.

These vectors prove that bytecrypt still opens old files after the change of the
on-disk format and the KDF. See [`FORMAT.md`](../../FORMAT.md) section 8. If a
refactor breaks the read support for an old format, this test fails.

## The one rule

**Never edit a vector and never generate a vector again to make a test pass.** A
wrong-password failure or a corruption failure on an existing vector is a real
backward compatibility regression. Fix the code, not the vector. A legacy blob
also cannot be reproduced byte for byte, because the salt is random and the
Fernet token holds a random IV and a timestamp.

## Vectors

| File | Format | Source | KDF |
|------|--------|--------|-----|
| `legacy-v0.3.1.bin` | legacy, no header | released tag `v0.3.1` | PBKDF2-HMAC-SHA512, 1000 iterations |
| `v1-scrypt.bin` | version 1 | bytecrypt 1.0, this repository | scrypt n=2^17, r=8, p=1 |

### Provenance of `legacy-v0.3.1`

This vector comes from the real released v0.3.1 code. The script loads the code
straight from git, so the working tree cannot influence it:

```python
src = subprocess.run(["git", "show", "v0.3.1:src/bytecrypt/bytecrypt.py"],
                     capture_output=True, text=True).stdout
ns = {}; exec(compile(src, "<v0.3.1>", "exec"), ns)
blob = ns["encrypt_bytes"](plaintext_utf8, password_utf8)   # salt(16) || Fernet token
```

The manifest holds the `password_utf8` and the `plaintext_utf8` of that run. Two
independent checks confirmed the vector. The first check was a round trip
through the same v0.3.1 code. The second check was a decryption with a new
implementation of the legacy KDF, written from FORMAT.md section 2.

Note: `0.3.2` never reached PyPI. The latest published release is `0.3.1`, and
`v0.3.1` is the latest tag. The legacy on-disk format is identical in all 0.x
releases. This single `v0.3.1` vector therefore represents each legacy file that
a user can have.

### Provenance of `v1-scrypt`

This vector comes from the `encrypt_bytes` function of this repository. It uses
the version 1 default layout, which is
`magic(4) || version(1) || salt(16) || token` with a scrypt key. You can generate
this vector again, but the committed `.bin` file stays fixed. It proves that a
future bytecrypt still reads version 1 data, for example after an Argon2id
default with the version byte `0x02` arrives.

## How to add a vector

FORMAT.md section 8 requires a new vector each time the default write format
changes, for example when version 1 with scrypt ships. Encrypt a known input with
the code that introduces the format. Commit the `.bin` file and a `.json`
manifest in the same shape as the existing files. `test_vectors.py` then finds
the new vector automatically.
