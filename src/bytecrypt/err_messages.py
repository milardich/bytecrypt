ERR_0 = "Error: missing -f FILE, -dir DIRECTORY or -str STRING option."
ERR_1 = "Error: pass only one flag (-e ENCRYPT or -d DECRYPT flag), not both."
ERR_2 = "Warning: (OPTIONAL) pass only one option (-efn ENCRYPT_FILENAME or -dfn DECRYPT_FILENAME flag.), not both."
ERR_3 = "Error: -p PASSWORD is required."
ERR_4 = "Error: pass only one option (-f FILE, -d DIRECTORY, -str STRING)."
ERR_5 = "Error: encrypting data and decrypting filename is not allowed."
ERR_6 = "Error: decrypting data and encrypting filename is not allowed."
ERR_7 = "Error: invalid arguments."


def print_err(err: str):
    print("\033[91m" + err + "\033[0m")


def print_info(info: str):
    print("\33[32m" + info + "\033[0m")


def print_warning(warning: str):
    print("\033[33m" + warning + "\033[0m")
