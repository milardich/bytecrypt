from bytecrypt import encrypt_bytes
from bytecrypt import decrypt_bytes
from bytecrypt import encrypt_directory
from bytecrypt import decrypt_directory
from bytecrypt import encrypt_file
from bytecrypt import decrypt_file
from bytecrypt import encrypt_string
from bytecrypt import decrypt_string
from argparse import ArgumentParser

### TODO
# list of directories or files
# e.g. -e -dir "test/directory1","testdir2" -p "test"
# e.g. -e -dir "test/secret.txt","binary.exe" -p "test"

### TODO
## recursive dir encrypt
# -r    || --recursive  (loops thru all dirs)

def init_argparse() -> ArgumentParser:
    parser = ArgumentParser(
        prog="Bytecrypt",
        description="Easy data encryption / decryption"
    )
    parser.add_argument('-e', '--encrypt', action='store_true')
    parser.add_argument('-d', '--decrypt', action='store_true')
    parser.add_argument('-f', '--file')
    parser.add_argument('-dir', '--directory')

    # TODO: directory encryption stuff
    parser.add_argument('-efn', '--encrypt_filename', action='store_true')
    parser.add_argument('-dfn', '--decrypt_filename', action='store_true')
    parser.add_argument('-r', '--recursive', action='store_true')

    parser.add_argument('-str', '--string')
    parser.add_argument('-p', '--password', required=True)
    return parser


def process_encrypting(args):
    if (args.directory and not args.file and not args.string):
        encrypt_directory(args.directory, bytes(args.password, encoding="utf-8"))
    elif (args.file and not args.directory and not args.string):
        encrypt_file(args.file, bytes(args.password, encoding="utf-8"), args.encrypt_filename)
    elif (args.string and not args.directory and not args.file):
        encrypt_string(args.string, bytes(args.password, encoding="utf-8"))
    else:
        print("\nWarning: passed more than one data argument (-dir, -file, -str)")


def process_decrypting(args):
    if (args.directory and not args.file and not args.string):
        decrypt_directory(args.directory, bytes(args.password, encoding="utf-8"))
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
    print("bytecrypt -e -s \"secret text\" -p testpassword")
    print("\nDecryption examples:")
    print("bytecrypt -d -f test.txt -p testpassword")
    print("bytecrypt -d -dir example/dir/test -p testpassword")
    print("bytecrypt -d -s \"EiDXFN...yUW0=\" -p testpassword")


def main():
    parser = init_argparse()
    args = parser.parse_args()
    # print(args)

    if (args.encrypt and not args.decrypt):
        process_encrypting(args)
    elif (args.decrypt and not args.encrypt):
        process_decrypting(args)
    elif (not args.decrypt and not args.encrypt):
        print("\nWarning: missing -d DECRYPT or -e ENCRYPT flag.")
        print_example()
    elif (not args.file and not args.directory and not args.string):
        print("\nWarning: missing -f FILE, -dir DIRECTORY or -str STRING option.")
        print_example()
    else:
        print("\nWarning: passed both -e ENCRYPT and -d DECRYPT flag.")
        print_example()


if __name__ == "__main__":
    main()

