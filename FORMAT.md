# bytecrypt encrypted file format

**Status:** draft for bytecrypt 1.0. **Defined format versions:** legacy (0.x)
and 1.

This document is the normative specification of the byte layout that bytecrypt
reads and writes. It keeps the format stable, auditable and backward compatible.
New releases must stay able to decrypt old files.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** have
the meaning that RFC 2119 gives them.

## Design goals

1. **Self-describing.** A blob carries the information that identifies its format
   and its key derivation parameters. It needs no sidecar file and no other
   metadata.
2. **Backward compatible.** bytecrypt decrypts the files of all released
   versions. The legacy 0.x format has no header, but bytecrypt detects it and
   reads it permanently.
3. **Aware of future formats.** bytecrypt detects a blob from a newer format and
   reports it as such. It does not fail with a generic crypto error.
4. **Simple and safe.** A single version byte selects the key derivation
   parameters from a fixed registry. The decryptor does not read cost parameters
   from the file. A crafted input therefore cannot exhaust the resources of the
   host.

## Notation

- A blob is the byte string that bytecrypt writes. `||` shows the concatenation
  of bytes. `0x..` shows a hexadecimal value. The defined integer fields are one
  byte each, thus no field has an endianness.
- A Fernet token is a token from `cryptography.fernet.Fernet.encrypt`. It is
  URL-safe base64 and contains a version, a timestamp, an IV, the ciphertext and
  an HMAC. The Fernet specification gives the details.

---

## 1. Version 1 format (the current default)

A version 1 blob has this layout:

```
magic || version || salt || token
```

| Offset | Size | Field   | Value or notes                                                     |
|-------:|-----:|---------|--------------------------------------------------------------------|
| 0      | 4    | magic   | `0x00 0x42 0x43 0x59`, which is `b"\x00BCY"`                        |
| 4      | 1    | version | `0x01`                                                             |
| 5      | 16   | salt    | 16 bytes from a secure random number generator. It MUST be unique. |
| 21     | ...  | token   | A Fernet token over the plaintext, with the key derived below.     |

The header is 21 bytes long. An encryptor **MUST** write new data in the current
default format, which is version 1.

### 1.1 Magic

The first byte of the magic is `0x00`. This byte separates a version 1 blob or a
later blob from a legacy blob. See section 3. A legacy blob cannot start with
`0x00`. Its first byte is a salt character from `[A-Za-z0-9_]`, which is the
range `0x30` to `0x7a`. Its other bytes are URL-safe base64.

A test on 14,000 legacy blobs confirmed this property. The blobs came from empty
inputs, textual inputs and binary inputs. All bytes were in the range `0x2d` to
`0x7a`, and no byte was `0x00`.

A future format version **MUST** keep a magic whose first byte is `0x00`, or a
byte outside the range `0x2d` to `0x7a`. Legacy detection then stays
unambiguous.

### 1.2 Key derivation: the version to KDF registry

The version byte selects a frozen parameter set. The decryptor looks the version
up in this registry. It **MUST NOT** read cost parameters from the blob.

| version | KDF       | Parameters                                   | Status                    |
|--------:|-----------|----------------------------------------------|---------------------------|
| `0x00`  | none      | none                                         | Reserved and invalid      |
| `0x01`  | scrypt    | `n = 2**17`, `r = 8`, `p = 1`, `length = 32` | **Defined, 1.0 default**  |
| `0x02`  | Argon2id  | not yet defined                              | Reserved and planned      |
| others  | none      | none                                         | Unassigned                |

For version `0x01`, bytecrypt derives the Fernet key as follows:

```python
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
raw = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password)  # 32 bytes
fernet_key = base64.urlsafe_b64encode(raw)                              # 44-char Fernet key
token = Fernet(fernet_key).encrypt(plaintext)
```

`scrypt(n=2**17, r=8, p=1)` follows the OWASP guidance for interactive use. One
derivation costs approximately 128 MiB of memory.

### 1.3 Password encoding

A password is a byte string. An implementation **MUST** encode a textual password
as UTF-8 before the key derivation. It applies no Unicode normalization. Two
different normalizations of the same password therefore derive different keys.
NFC normalization is a deliberate non-goal for 1.0. It changes the derived keys,
thus only a new format version can introduce it.

---

## 2. Legacy format (0.x), read only

The files of bytecrypt 0.x have no header:

```
salt || token
```

| Offset | Size | Field | Notes                                                             |
|-------:|-----:|-------|-------------------------------------------------------------------|
| 0      | 16   | salt  | 16 ASCII characters from `[A-Za-z0-9_]`, from a non-secure source. |
| 16     | ...  | token | A Fernet token.                                                   |

bytecrypt derives the legacy key as follows. This code is for read
compatibility only:

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
raw = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=1000).derive(password)
fernet_key = base64.urlsafe_b64encode(raw)
```

An implementation of bytecrypt 1.x **MUST** decrypt a legacy blob. It **MUST
NOT** write the legacy format. The legacy format is cryptographically weak,
because it uses 1,000 PBKDF2 iterations and a non-secure salt. See section 5 and
section 6.

---

## 3. Format detection, the decryption dispatch

```
function decrypt(blob, password):
    if len(blob) >= 5 and blob[0:4] == MAGIC:          # version 1 or later
        version = blob[4]
        if version not in REGISTRY:
            raise UnsupportedFormatError              # "needs a newer bytecrypt; pip install -U"
        salt  = blob[5:21]
        token = blob[21:]
        key   = derive(REGISTRY[version], password, salt)
    elif len(blob) >= MIN_LEGACY_LEN:                  # legacy 0.x, no magic
        salt  = blob[0:16]
        token = blob[16:]
        key   = legacy_pbkdf2_sha512_1000(password, salt)
    else:
        raise NotBytecryptFileError                    # too short or unknown

    try:
        return Fernet(key).decrypt(token)
    except InvalidToken:
        raise InvalidPasswordError                     # wrong password or damaged data
```

`MIN_LEGACY_LEN` is 16 plus the minimum length of a Fernet token. Fernet fixes
that minimum. The token holds a version byte, an 8-byte timestamp, a 16-byte IV,
a ciphertext of 16 bytes or more, and a 32-byte HMAC. It holds all of this in
base64. A legacy blob is therefore approximately 116 bytes long or longer.

---

## 4. Error conditions

An implementation **SHOULD** separate these cases and give a clear message for
each one:

| Situation                                    | Result                                                          |
|----------------------------------------------|-----------------------------------------------------------------|
| Magic present, version in the registry       | Decrypt the data.                                               |
| Magic present, version not in the registry   | `UnsupportedFormatError`: a newer bytecrypt wrote this file.     |
| No magic, valid legacy blob                  | Decrypt the data. See section 6 for the weak legacy format.      |
| No magic, too short or not a Fernet token    | `NotBytecryptFileError`: this is not a bytecrypt file.           |
| Known format, authentication fails           | `InvalidPasswordError`: wrong password or damaged file.          |

The magic makes a version 1 blob detectable. An encryptor **SHOULD** therefore
give a warning before it encrypts a blob that starts with the magic. This
prevents accidental double encryption. The detection works only for version 1 and
later. A legacy blob looks like arbitrary text, so bytecrypt cannot detect it as
already encrypted.

---

## 5. Security considerations

- **The header is not authenticated.** Fernet has no AAD, so the authentication
  tag does not cover the magic, the version and the salt. A change to these bytes
  makes the implementation derive a wrong key, and Fernet then rejects the token
  with `InvalidToken`. This behavior fails closed. An attacker cannot force a
  wrong plaintext and cannot forge a valid blob with an edit to the header. A
  fully authenticated header needs a different primitive than Fernet, which is
  out of scope for this format version.
- **No parameters from an untrusted source.** The cost parameters come from the
  registry, and the version byte selects them. The implementation does not read
  them from the blob. A crafted or damaged file therefore cannot cause a large
  memory allocation. A header with `log2_n`, `r` and `p` fields would create that
  risk without a bounds check.
- **Salt.** A version 1 salt **MUST** come from a secure random number generator.
  A salt is not secret, but it **MUST** be unique for each encryption.
- **Memory cost.** scrypt with `n = 2**17` uses approximately 128 MiB for each
  derivation. A host that runs many derivations in parallel can exhaust its own
  memory. For the CLI and for single files this cost is acceptable.
- **Weak legacy format.** The legacy format uses 1,000 PBKDF2 iterations, which
  is far below the current guidance, and its salt does not come from a secure
  source. bytecrypt reads legacy files for data continuity only. Users **SHOULD**
  migrate their legacy files. See section 7.

---

## 6. Compatibility policy

- **The format version is not the package version.** The package follows SemVer.
  The format has its own small integer registry. More than one package version
  can read and write the same format version. The release notes of each release
  **SHOULD** give the format versions that it reads, and the format version that
  it writes.
- **Legacy reads stay permanent in 1.x.** A release that removes the read support
  for an old format strands the data of the users. A minor release or a patch
  release **MUST NOT** do this. Such a change is a major version change, and it
  needs a long and clear deprecation period.
- **A change of the default write format** is a change such as the introduction
  of `0x02`. An old installation cannot read the files of the new version. The
  release notes **MUST** announce such a change prominently.

---

## 7. Migration

A re-encryption operation moves a file from an old format or KDF to the current
default. An example is a move from the legacy PBKDF2 format to scrypt. The
operation has these properties:

- It **MUST** decrypt the data and encrypt it again fully in memory. It **MUST
  NOT** write the plaintext to disk.
- It **MUST** write the result atomically: a temporary file in the same
  directory, then `flush` and `fsync`, then `os.replace`. This is the behavior of
  all encrypt operations.
- It **SHOULD** be idempotent. The magic identifies a file that is already at the
  current default version, and the operation leaves such a file unchanged. A run
  after an interruption therefore completes the remaining files.

---

## 8. Test vectors

Regression vectors in `tests/vectors/` guarantee the backward compatibility:

- Each vector is a real blob from a specific released version. A small manifest
  holds its password and its expected plaintext.
- A CI test decrypts each vector on each supported Python version, and it
  compares the plaintext. CI fails if a refactor breaks the read support for an
  old format.
- The legacy vector **MUST** come from real released code, which is the `v0.3.1`
  tag. That tag is the latest release, because `0.3.2` never reached PyPI, and
  the legacy format is identical in all 0.x releases. Check out the tag, encrypt
  a known input and commit the bytes. A later run cannot reproduce a legacy blob
  exactly. The committed file is `legacy-v0.3.1.bin`.
- Add a new vector each time the default write format changes.

---

## 9. Format version history

| Format    | Introduced | KDF                       | Notes                                        |
|-----------|------------|---------------------------|----------------------------------------------|
| legacy    | 0.x        | PBKDF2-HMAC-SHA512, 1000  | No header. Read only in 1.x. Weak.           |
| version 1 | 1.0        | scrypt n=2^17, r=8, p=1   | Self-describing header. Secure random salt.  |
