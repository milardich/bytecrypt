# Changelog

## 1.0.0

The first stable release. bytecrypt writes new data in a stronger, versioned
format. It still decrypts all data that the 0.x releases wrote.

### Security
- The key derivation moves from PBKDF2-HMAC-SHA512 with 1,000 iterations to
  scrypt with n = 2^17, r = 8 and p = 1.
- Each salt now comes from a secure random number generator
  (`secrets.token_bytes`) instead of `random`.

### On-disk format
- New versioned format: `magic || version || salt || token`. See
  [FORMAT.md](FORMAT.md). The version byte selects the key derivation parameters
  from a fixed registry. bytecrypt does not read the cost parameters from the
  file, so a crafted blob cannot cause a large memory allocation.
- bytecrypt detects a legacy 0.x file, which has no header, and decrypts it. It
  does not write the legacy format.

### Reliability
- Atomic writes: a temporary file, then `fsync`, then `os.replace`. An
  interrupted operation or a wrong password can no longer damage or truncate a
  file.
- The file system paths use `os.path` and `os.walk`. This fixes the relocation of
  files to the working directory on Windows. A directory walk no longer follows a
  symbolic link.

### API and CLI
- A password can be a `str` or `bytes`.
- `pip install bytecrypt` now installs a `bytecrypt` command through an entry
  point.
- The import of the package is silent and has no side effect. bytecrypt reads the
  version from the installed package metadata. It does not read
  `pyproject.toml` at runtime.
- The library functions raise typed errors instead of printing a message. The
  base class is `BytecryptError`, and the subclasses are
  `InvalidPasswordError`, `NotBytecryptFileError`, `UnsupportedFormatError`,
  `AlreadyEncryptedError` and `FileNameTooLongError`. The CLI prints to stderr
  and exits with a non-zero code after a failure.
- The `-p` option is now optional. The CLI asks for the password with `getpass`,
  and it asks two times when it encrypts.
- New options: `--reencrypt` migrates a legacy file to the current format, or
  changes the password with `-np`. `--force` encrypts data that is already
  encrypted.
- The keywords `encrypt_filename` and `decrypt_filename` now match the `-efn` and
  `-dfn` options of the CLI and the README.

### Requirements
- Python 3.11 or later. The previous requirement was 3.9. The `cryptography`
  wheel sets this floor.

### Upgrade
Old files and old strings still decrypt. To move them to scrypt, run
`bytecrypt --reencrypt -f <file>` or `bytecrypt --reencrypt -dir <directory> -r`.
