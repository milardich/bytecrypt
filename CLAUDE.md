# CLAUDE.md

This file gives guidance to Claude Code (claude.ai/code) for work in this
repository.

## Overview

bytecrypt is a Python package and a CLI. It encrypts and decrypts byte strings,
files and directories with a password. PyPI holds it as `bytecrypt`. The
releases also contain standalone PyInstaller executables for Windows and Linux.

Since **1.0** it derives keys with **scrypt**, writes a **versioned
self-describing format**, writes files **atomically** and raises **typed
errors**. It requires **Python 3.11 or later**. The only runtime dependency is
`cryptography`.

## Commands

```sh
# Install for local development (editable, with test deps)
python -m pip install -e ".[test]"   # or: ./install_editable.ps1

# Run the CLI after install
bytecrypt -e -f test.txt -p mypassword
python -m bytecrypt -e -f test.txt -p mypassword   # without install

# Test + format
python -m pytest                     # full suite
python -m pytest tests/test_vectors.py
python -m yapf -i -r src tests       # format in place (CI runs --diff and fails on drift)

# Build standalone executable (requires pyinstaller)
./build_executable.ps1               # Windows -> dist/bytecrypt.exe
./build_executable.sh                # Linux   -> dist/bytecrypt

# Publish: a published GitHub Release triggers the workflows (PyPI via OIDC +
# exe build/attach). ./upload_pypi.ps1 is the manual twine fallback.
```

## Testing

A pytest suite exists in `tests/`. The configuration is in `pyproject.toml`,
section `[tool.pytest.ini_options]`. All tests run against `tmp_path`, thus a
test never changes the fixture files of the repository.

- **`test_roundtrip.py`** tests the encrypt and decrypt round trips for bytes,
  strings, files and directories, recursive and not recursive. It also tests the
  file name encryption and the wrong password. A wrong password raises an error
  and leaves the bytes unchanged.
- **`test_format.py`** tests the detection of the versioned format, the decrypt
  dispatch, the typed errors and the rejection of a changed blob. See FORMAT.md
  sections 3 and 4.
- **`test_migration.py`** tests `--reencrypt`: the migration from legacy to
  version 1, the idempotency and the password change. See FORMAT.md section 7.
- **`test_cli.py`** tests the CLI from end to end with `python -m bytecrypt`. It
  covers the argument handling, the stdout output and the non-zero exit code.
- **`test_vectors.py`** decrypts each `tests/vectors/*.bin` file against its
  `.json` manifest. This test protects the backward compatibility.

**Never change a regression vector.** The files in `tests/vectors/*.bin` are real
blobs from released code. One example is `legacy-v0.3.1.bin` from the real
`v0.3.1` tag. Never edit a vector and never generate a vector again to make a
test pass.

A failure there is a real backward compatibility regression, so fix the code.
See `tests/vectors/README.md`. Add a new vector each time the default *write*
format changes.

## Architecture

The source uses a `src/` layout. The package is `src/bytecrypt/`.

- **`bytecrypt.py`** holds all crypto logic, all file system logic and the typed
  error classes. It is the public API.
- **`__init__.py`** re-exports the public functions and errors. It resolves
  `__version__` with `importlib.metadata.version("bytecrypt")`, and it falls back
  to `"0.0.0+source"` in a source tree without an install. **The import of the
  package is silent and has no side effect.** It prints no version and starts no
  shell.
- **`__main__.py`** holds the argparse CLI. `check_args` validates the mutually
  exclusive option combinations against the `ERR_*` constants. `run` dispatches
  to the directory, file and string functions. The CLI asks for the password with
  `getpass` when the user omits `-p`. It asks two times on encrypt.
  `os.system("")` enables the ANSI colors on a legacy Windows terminal. That call
  lives here in `main()`, and the condition `os.name == "nt"` guards it. It does
  **not** run on import. An argument error exits with `2`. A `BytecryptError` or
  an `OSError` prints to stderr and exits with `1`. Success exits with `0`.
- **`err_messages.py`** holds the `ERR_*` message strings and the `print_err` and
  `print_info` helpers, which are ANSI wrappers. Errors go to **stderr**, and
  information goes to **stdout**. The CLI entry point enables the ANSI colors,
  not this module.

### Crypto scheme and on-disk format (bytecrypt.py)

**[FORMAT.md](FORMAT.md) specifies the byte layout normatively, and the code
follows it.** A change to the format needs a read and an update of FORMAT.md too.

`encrypt_bytes` and `decrypt_bytes` are the core primitives. All other functions
build on them.

- **bytecrypt always writes new data as version 1:**
  `magic(4) || version(1) || salt(16) || fernet_token`, where
  `magic = b"\x00BCY"`. It derives the key with **scrypt**
  (`n=2**17, r=8, p=1, length=32`). `Fernet` (AES-128-CBC + HMAC) then seals the
  plaintext. The salt is 16 new bytes from `secrets`.
- **bytecrypt still decrypts legacy 0.x data** (`salt(16) || fernet_token`,
  PBKDF2-HMAC-SHA512 with 1000 iterations, no header). It reads this format
  permanently, but it never writes it.
- **The decryption dispatches on the magic.** If the magic is present, bytecrypt
  looks the version up in `_KDF_REGISTRY`, which is a fixed table. It NEVER reads
  the cost parameters from the blob, which is the anti-DoS property. If the magic
  is absent, it uses the legacy path. A blob that is too short or unknown raises
  `NotBytecryptFileError`.
- `looks_encrypted` detects only **version 1 and later** blobs, because it looks
  for the magic. A legacy blob looks like arbitrary text, so bytecrypt cannot
  detect it reliably.
- Strings and file names are **base64-encoded** for transport. A version 1 blob
  starts with a NUL byte and holds a binary salt, so it does not work as text.
  `_decode_token` accepts both forms: base64 of a version 1 blob, and a raw
  legacy token.

### The one invariant: never lock out existing data

bytecrypt 1.x must keep the read support for each format that it wrote before.
Therefore: **do not change the salt length, the KDF parameters or the layout of
an existing version in place.** A crypto change needs a *new* version byte in
`_KDF_REGISTRY`, a new entry in FORMAT.md sections 1.2 and 9, and a committed
regression vector. Never edit version 1 silently. The removal of a read path is a
major version event with a loud deprecation. The byte `0x02` is reserved for a
future Argon2id default.

### File system behavior

- `encrypt_file` and `decrypt_file` read the full file, then write it with
  **`_atomic_write`**: a temp file in the same directory, then `flush` and
  `fsync`, then `os.replace`. A crash leaves **no half-written file**. A **wrong
  password on decrypt leaves the original file untouched**, because the
  decryption fails before any write. There is still no separate backup copy.
- `encrypt_file` and `encrypt_directory` refuse input that is already encrypted
  as version 1, unless `force=True`. They raise `AlreadyEncryptedError`.
  `encrypt_directory` pre-scans the files, so it runs fully or refuses at the
  start. A partially encrypted tree does not occur.
- The file name encryption (`encrypt_file_name` and `decrypt_file_name`)
  base64-encodes the encrypted name and renames the file with `os.replace`. It
  refuses a name longer than `MAX_FILENAME_LEN` (255) and raises
  `FileNameTooLongError`.
- The directory traversal uses `_iter_files`, which calls `os.walk` when
  recursive and `os.listdir` when not recursive. It **skips symbolic links and
  never follows them**.
- `reencrypt_file` and `reencrypt_directory` are the `--reencrypt` migration.
  They decrypt and encrypt again **fully in memory**, so the plaintext never
  reaches the disk. They write atomically and are **idempotent**. They skip a
  file that is already at the current version when the password does not change,
  thus an interrupted migration can continue. They are also the password change
  path, through `new_password`.

### Path handling

The path handling uses `os.path` (`split`, `join`, `dirname`, `abspath`) and
`os.walk` everywhere. It is therefore correct on Windows. Pre-1.0 code split the
path on `'/'` and moved files to the CWD on Windows. Do not add manual `'/'`
parsing again.

### Errors

All errors inherit from `BytecryptError`:

- `InvalidPasswordError`: wrong password, or a damaged or changed blob.
- `NotBytecryptFileError`: the input is not a bytecrypt blob.
- `UnsupportedFormatError`: the file needs a newer bytecrypt.
- `AlreadyEncryptedError`: the guard against double encryption.
- `FileNameTooLongError`: the encrypted file name is too long.

The library raises the errors. Only the CLI prints a message and sets the exit
code.

## Versioning

`pyproject.toml`, key `[project].version`, is the single source of truth. The
build and the publish use it, and `importlib.metadata` reports it for an
installed package. bytecrypt does **not read `pyproject.toml` at runtime**, and
the build scripts have **no `--add-data` option**. Version 1.0 removed both. To
bump the version, edit `pyproject.toml` and add a `CHANGELOG.md` entry. If the
default *write* format changed, commit a new regression vector too.

## Key docs

- **[FORMAT.md](FORMAT.md)** is the normative on-disk format specification. It
  holds the byte tables, the dispatch, the KDF registry, the compatibility policy
  and the rules for the test vectors. It is the source of truth for the format.
- **[CHANGELOG.md](CHANGELOG.md)** holds the release notes. Each entry states the
  format versions that the release reads and writes.
