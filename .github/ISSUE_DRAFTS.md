# Issue drafts, follow-up work after 1.0

This file is a paste buffer for the GitHub issues to file after the 1.0 release,
when the repository is set up. **Delete this file after the issues exist on
GitHub.** It must not become the next ROADMAP.md.

The drafts below use these labels. Create them one time:

```sh
gh label create enhancement  --color 0e8a16 --description "New feature or improvement"
gh label create format       --color 5319e7 --description "Touches the on-disk format (FORMAT.md)"
gh label create cli          --color 1d76db --description "Command-line interface"
gh label create needs-design --color fbca04 --description "Design decision required before coding"
```

---

## 1. Streaming encryption in chunks for large files

**Labels:** `enhancement`, `format`, `needs-design`

```md
### Problem
`encrypt_file` and `decrypt_file` read the full file into memory, and Fernet has
no streaming API. A file larger than the available memory therefore does not
work. bytecrypt also holds the plaintext and the ciphertext in memory at the same
time for a short period.

### Proposed approach
Fernet cannot stream, so this needs a new format version, for example `0x03`,
with a layout in chunks. Use frames of a fixed size. Authenticate each frame
separately. Give each frame a sequence number, and add an explicit end-of-stream
marker. bytecrypt then detects a truncation and a reorder of the frames. The
decryption writes frame by frame into the atomic temporary file.

### Constraints and acceptance
- bytecrypt encrypts and decrypts a file larger than the available memory
  without a full read.
- Add the new version to `_KDF_REGISTRY`, to FORMAT.md section 1.2 and to
  FORMAT.md section 9. Commit a regression vector, as FORMAT.md section 8
  requires. Existing version 1 files must still decrypt.
- Keep the atomic write. Decide the default chunk size.

Compare this work against the goal of simplicity. It adds real complexity, so
ship it only if users want support for large files.
```

---

## 2. Argon2id KDF as format version 0x02, opt-in

**Labels:** `enhancement`, `format`, `needs-design`

```md
### Context
FORMAT.md already reserves the version `0x02` for Argon2id. scrypt, which is
`0x01`, stays the default. The read path stays permanent in each case.

### Decision needed first
Argon2id needs the `argon2-cffi` dependency, which conflicts with the promise of
one dependency. There are two options:
1. An opt-in extra: `pip install bytecrypt[argon2]`. A user needs the extra to
   write `0x02`. A user also needs the extra to read `0x02`.
2. No release until real demand exists. The version `0x02` stays reserved.

### Acceptance, if the work continues
- `0x02` writes and reads Argon2id with fixed parameters from the registry.
  bytecrypt never reads them from the blob, which is the same rule as for `0x01`.
- Fill in FORMAT.md section 1.2 and section 9. Commit a regression vector.
  `--reencrypt` migrates `0x01` to `0x02`.
- scrypt stays the default write format until a deliberate decision changes it.
  A change of the default write version needs a prominent announcement.
```

---

## 3. Accept more than one file or directory in one CLI call

**Labels:** `enhancement`, `cli`

```md
### Problem
The CLI takes one target. The options `-f`, `-dir` and `-str` form one mutually
exclusive group, and each option accepts one value. A command such as
`bytecrypt -e -f a.txt b.txt c.txt` does not work.

### Proposed approach
Accept more than one value, for example with `nargs="+"` on `-f` and `-dir`, or
with repeatable options. Then loop over the targets. This has no format impact.
It touches only the CLI layer and the argument validation.

### Details to get right
- Extend the all-or-nothing pre-scan of the directory path, which raises
  `AlreadyEncryptedError`, across all targets. The full call then runs completely
  or stops at the start.
- Decide the exit code for a partial failure, for example one wrong password in
  the middle of a batch. Choose between a stop at the first error and a
  continuation with a report at the end. Document the decision.
- Keep `-str` at one value, because a token is not a batch.
```
