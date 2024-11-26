from bytecrypt import encrypt_directory
from bytecrypt import decrypt_directory
from bytecrypt import encrypt_file
from bytecrypt import decrypt_file
from bytecrypt import encrypt_string
from bytecrypt import decrypt_string
from argparse import ArgumentParser
from bytecrypt.err_messages import *
import sys

# TODO
# list of directories or files
# e.g. -e -dir "test/directory1","testdir2" -p "test"
# e.g. -e -dir "test/secret.txt","binary.exe" -p "test"


def init_argparse() -> ArgumentParser:
    parser = ArgumentParser(prog="Bytecrypt",
                            description="Easy data encryption / decryption")
    parser.add_argument('-e', '--encrypt', action='store_true')
    parser.add_argument('-d', '--decrypt', action='store_true')
    parser.add_argument('-f', '--file')
    parser.add_argument('-dir', '--directory')
    parser.add_argument('-efn', '--encrypt_filename', action='store_true')
    parser.add_argument('-dfn', '--decrypt_filename', action='store_true')
    parser.add_argument('-str', '--string')
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-r', '--recursive', action='store_true')
    return parser


#dir_action      -> encrypt_directory or decrypt_directory : function
#file_action     -> encrypt_file or decrypt_file : function
#string_action   -> encrypt_string or decrypt_string : function
def process_action(dir_action, file_action, string_action, args):
    string = args.string
    file = args.file
    directory = args.directory
    recursive = args.recursive
    password = args.password
    name_action = args.encrypt_filename or args.decrypt_filename

    if (directory):
        dir_action(directory, bytes(password, encoding="utf-8"), name_action,
                   recursive)
    elif (file):
        file_action(file, bytes(password, encoding="utf-8"), name_action)
    elif (string):
        string_action(string, bytes(password, encoding="utf-8"))
    else:
        print_err(ERR_4)


def print_example():
    print("\nEncryption examples:")
    print("bytecrypt -e -f test.txt -p testpassword")
    print("bytecrypt -e -dir example/dir/test -p testpassword")
    print("bytecrypt -e -str \"secret text\" -p testpassword")
    print("\nDecryption examples:")
    print("bytecrypt -d -f test.txt -p testpassword")
    print("bytecrypt -d -dir example/dir/test -p testpassword")
    print("bytecrypt -d -str \"EiDXFN...yUW0=\" -p testpassword")


def check_args(args) -> bool:
    encrypting = args.encrypt
    decrypting = args.decrypt
    string = args.string
    file = args.file
    encrypt_filename = args.encrypt_filename
    decrypt_filename = args.decrypt_filename
    directory = args.directory
    recursive = args.recursive
    password = args.password

    if (not file and not directory and not string):
        print_err(ERR_0)
        print_example()
        return False
    if (encrypting and decrypting):
        print_err(ERR_1)
        print_example()
        return False
    if (encrypt_filename and decrypt_filename):
        print_err(ERR_2)
        print_example()
        return False
    if (not password):
        print_err(ERR_3)
        print_example()
        return False
    if (file and directory):
        print_err(ERR_4)
        print_example()
        return False
    if (file and string):
        print_err(ERR_4)
        print_example()
        return False
    if (string and directory):
        print_err(ERR_4)
        print_example()
        return False
    if (encrypting and decrypt_filename):
        print_err(ERR_5)
        print_example()
        return False
    if (decrypting and encrypt_filename):
        print_err(ERR_6)
        print_example()
        return False
    return True


def main():
    parser = init_argparse()
    args = parser.parse_args()
    valid_args = check_args(args)

    if (valid_args):
        if (args.encrypt):
            process_action(encrypt_directory, encrypt_file, encrypt_string,
                           args)
        elif (args.decrypt):
            process_action(decrypt_directory, decrypt_file, decrypt_string,
                           args)
    else:
        print_err(ERR_7)
        sys.exit(0)


if __name__ == "__main__":
    main()