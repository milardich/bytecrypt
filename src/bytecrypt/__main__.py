"""
Command line interface for bytecrypt.
"""

import getpass
import os
import sys
from argparse import ArgumentParser

from bytecrypt import (
    BytecryptError,
    decrypt_directory,
    decrypt_file,
    decrypt_string,
    encrypt_directory,
    encrypt_file,
    encrypt_string,
    reencrypt_directory,
    reencrypt_file,
)
from bytecrypt.err_messages import (
    ERR_BOTH_FILENAME,
    ERR_DEC_WITH_EFN,
    ERR_ENC_WITH_DFN,
    ERR_FILENAME_WITH_STRING,
    ERR_NO_TARGET,
    print_err,
    print_info,
)


def init_argparse() -> ArgumentParser:
    parser = ArgumentParser(
        prog="bytecrypt",
        description="Encrypt and decrypt data with a password.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-e",
                      "--encrypt",
                      action="store_true",
                      help="encrypt the target")
    mode.add_argument("-d",
                      "--decrypt",
                      action="store_true",
                      help="decrypt the target")
    mode.add_argument(
        "--reencrypt",
        action="store_true",
        help="write the target again in the current format, or change the "
        "password with --new-password")

    target = parser.add_mutually_exclusive_group()
    target.add_argument("-f", "--file", help="use a file as the target")
    target.add_argument("-dir",
                        "--directory",
                        help="use a directory as the target")
    target.add_argument("-str", "--string", help="use a string as the target")

    parser.add_argument("-efn",
                        "--encrypt-filename",
                        dest="encrypt_filename",
                        action="store_true",
                        help="encrypt the file name too")
    parser.add_argument("-dfn",
                        "--decrypt-filename",
                        dest="decrypt_filename",
                        action="store_true",
                        help="decrypt the file name too")
    parser.add_argument("-p",
                        "--password",
                        help="the password (bytecrypt asks for it if you omit "
                        "this option)")
    parser.add_argument("-np",
                        "--new-password",
                        help="the new password, with --reencrypt")
    parser.add_argument("-r",
                        "--recursive",
                        action="store_true",
                        help="include the subdirectories")
    parser.add_argument("-F",
                        "--force",
                        action="store_true",
                        help="encrypt the data again, also when it is already "
                        "encrypted")
    return parser


def print_example() -> None:
    print("\nExamples:")
    print("  bytecrypt -e -f secret.txt -p mypassword")
    print("  bytecrypt -d -f secret.txt           "
          "(bytecrypt asks for the password)")
    print("  bytecrypt -e -dir my/directory -r -p mypassword")
    print("  bytecrypt -e -str \"secret text\" -p mypassword")
    print("  bytecrypt --reencrypt -f old.txt -p oldpw -np newpw")


def check_args(args) -> bool:
    if not (args.encrypt or args.decrypt or args.reencrypt):
        print_err("pass one of -e/--encrypt, -d/--decrypt or --reencrypt")
        return False
    if not (args.file or args.directory or args.string):
        print_err(ERR_NO_TARGET)
        return False
    if args.encrypt_filename and args.decrypt_filename:
        print_err(ERR_BOTH_FILENAME)
        return False
    if args.string and (args.encrypt_filename or args.decrypt_filename):
        print_err(ERR_FILENAME_WITH_STRING)
        return False
    if args.encrypt and args.decrypt_filename:
        print_err(ERR_ENC_WITH_DFN)
        return False
    if args.decrypt and args.encrypt_filename:
        print_err(ERR_DEC_WITH_EFN)
        return False
    return True


def resolve_password(args, confirm: bool) -> str:
    if args.password is not None:
        return args.password
    password = getpass.getpass("Password: ")
    if confirm and password != getpass.getpass("Confirm password: "):
        raise BytecryptError("passwords do not match")
    return password


def run(args) -> None:
    name_action = args.encrypt_filename or args.decrypt_filename

    if args.encrypt:
        password = resolve_password(args, confirm=True)
        if args.directory:
            encrypt_directory(args.directory, password, name_action,
                              args.recursive, args.force)
        elif args.file:
            encrypt_file(args.file,
                         password,
                         encrypt_filename=name_action,
                         force=args.force)
        else:
            print(encrypt_string(args.string, password))

    elif args.decrypt:
        password = resolve_password(args, confirm=False)
        if args.directory:
            decrypt_directory(args.directory, password, name_action,
                              args.recursive)
        elif args.file:
            decrypt_file(args.file, password, decrypt_filename=name_action)
        else:
            print(decrypt_string(args.string, password))

    else:  # --reencrypt
        if args.string:
            raise BytecryptError("--reencrypt applies to -f/-dir, not -str")
        password = resolve_password(args, confirm=False)
        if args.directory:
            count = reencrypt_directory(args.directory, password,
                                        args.new_password, args.recursive)
            print_info("re-encrypted %d file(s)" % count)
        else:
            changed = reencrypt_file(args.file, password, args.new_password)
            print_info("re-encrypted" if changed else "already at the current "
                       "version, file unchanged")


def main() -> None:
    if os.name == "nt":
        os.system("")  # enable ANSI colors on legacy Windows 10 terminals

    args = init_argparse().parse_args()
    if not check_args(args):
        print_example()
        sys.exit(2)

    try:
        run(args)
    except (BytecryptError, OSError) as err:
        print_err("error: " + str(err))
        sys.exit(1)


if __name__ == "__main__":
    main()
