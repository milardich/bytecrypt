from bytecrypt import encrypt_bytes
from bytecrypt import decrypt_bytes
from bytecrypt import encrypt_directory
from bytecrypt import decrypt_directory
from bytecrypt import encrypt_file
from bytecrypt import decrypt_file
from bytecrypt import encrypt_string
from bytecrypt import decrypt_string
from argparse import ArgumentParser
import sys

### TODO
# list of directories or files
# e.g. -e -dir "test/directory1","testdir2" -p "test"
# e.g. -e -dir "test/secret.txt","binary.exe" -p "test"

### TODO
## recursive dir encrypt
# -r    || --recursive  (loops thru all dirs)

### TODO
# refactor everything

def init_argparse() -> ArgumentParser:
    parser = ArgumentParser(
        prog="Bytecrypt",
        description="Easy data encryption / decryption"
    )
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



def process_encrypting(args):
    if (args.directory and not args.file and not args.string):
        encrypt_directory(args.directory, bytes(args.password, encoding="utf-8"), args.encrypt_filename, args.recursive)
    elif (args.file and not args.directory and not args.string):
        encrypt_file(args.file, bytes(args.password, encoding="utf-8"), args.encrypt_filename)
    elif (args.string and not args.directory and not args.file):
        encrypt_string(args.string, bytes(args.password, encoding="utf-8"))
    else:
        print("\nWarning: passed more than one data argument (-dir, -file, -str)")



def process_decrypting(args):
    if (args.directory and not args.file and not args.string):
        decrypt_directory(args.directory, bytes(args.password, encoding="utf-8"), args.decrypt_filename, args.recursive)
    elif (args.file and not args.directory and not args.string):
        decrypt_file(args.file, bytes(args.password, encoding="utf-8"), args.decrypt_filename)
    elif (args.string and not args.directory and not args.file):
        decrypt_string(args.string, bytes(args.password, encoding="utf-8"))
    else:
        print("\nWarning: passed more than one data argument (-dir, -file, -str)")



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
    password = args.password

    if (not file and not directory and not string):
        print("\nWarning: missing -f FILE, -dir DIRECTORY or -str STRING option.")
        print_example()
        return False
    if (encrypting and decrypting):
        print("\nWarning: pass only one flag (-e ENCRYPT or -d DECRYPT flag), not both.")
        print_example()
        return False
    if (encrypt_filename and decrypt_filename):
        print("\nWarning: (OPTIONAL) pass only one option (-efn ENCRYPT_FILENAME or -dfn DECRYPT_FILENAME flag.), not both.")
        print_example()
        return False
    if (not password):
        print("\nWarning: -p PASSWORD is required.")
        print_example()
        return False
    if (file and directory):
        print("\nWarning: pass only one option (-f FILE, -d DIRECTORY, -str STRING)")
        print_example()
        return False
    if (file and string):
        print("\nWarning: pass only one option (-f FILE, -d DIRECTORY, -str STRING)")
        print_example()
        return False
    if (string and directory):
        print("\nWarning: pass only one option (-f FILE, -d DIRECTORY, -str STRING)")
        print_example()
        return False
    if (encrypting and decrypt_filename):
        print("\nWarning: encrypting data and decrypting filename is not allowed")
        print_example()
        return False
    if (decrypting and encrypt_filename):
        print("\nWarning: decrypting data and encrypting filename is not allowed")
        print_example()
        return False
    return True



def main():
    parser = init_argparse()
    args = parser.parse_args()
    valid_args = check_args(args)

    if (valid_args):
        if (args.encrypt):
            process_encrypting(args)
        elif (args.decrypt):
            process_decrypting(args)
    else:
        print("\nError: invalid arguments.")
        sys.exit(0)



if __name__ == "__main__":
    main()

