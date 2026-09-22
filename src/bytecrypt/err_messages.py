import sys

ERR_NO_TARGET = "missing -f FILE, -dir DIRECTORY or -str STRING"
ERR_BOTH_FILENAME = "pass only one of -efn or -dfn"
ERR_ENC_WITH_DFN = "-dfn does not work with -e. Use -efn to encrypt a file name"
ERR_DEC_WITH_EFN = "-efn does not work with -d. Use -dfn to decrypt a file name"
ERR_FILENAME_WITH_STRING = "-efn and -dfn do not apply to -str STRING"


def print_err(message: str) -> None:
    print("\033[91m" + str(message) + "\033[0m", file=sys.stderr)


def print_info(message: str) -> None:
    print("\033[32m" + str(message) + "\033[0m")
