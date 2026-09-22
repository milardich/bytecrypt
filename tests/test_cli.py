"""End-to-end CLI tests through `python -m bytecrypt`.

These tests run the real entry point. They cover the argument handling, the
stdout output for a string and the non-zero exit code after a failure. They pass
-p, thus getpass does not ask for a password.
"""

import subprocess
import sys


def _run(args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "bytecrypt", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True
    )


def test_cli_file_roundtrip(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_bytes(b"cli secret\n")

    r = _run(["-e", "-f", str(p), "-p", "pw"], tmp_path)
    assert r.returncode == 0, r.stderr
    assert p.read_bytes() != b"cli secret\n"

    r = _run(["-d", "-f", str(p), "-p", "pw"], tmp_path)
    assert r.returncode == 0, r.stderr
    assert p.read_bytes() == b"cli secret\n"


def test_cli_string_roundtrip(tmp_path):
    r = _run(["-e", "-str", "hello cli", "-p", "pw"], tmp_path)
    assert r.returncode == 0, r.stderr
    token = r.stdout.strip().splitlines()[-1]

    r = _run(["-d", "-str", token, "-p", "pw"], tmp_path)
    assert r.returncode == 0, r.stderr
    assert "hello cli" in r.stdout


def test_cli_wrong_password_exits_nonzero(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_bytes(b"data")
    _run(["-e", "-f", str(p), "-p", "pw"], tmp_path)

    r = _run(["-d", "-f", str(p), "-p", "wrong"], tmp_path)
    assert r.returncode == 1
    assert "error" in r.stderr.lower()


def test_cli_no_args_is_usage_error(tmp_path):
    r = _run([], tmp_path)
    assert r.returncode == 2
