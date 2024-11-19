from bytecrypt import encrypt_bytes
from bytecrypt import decrypt_bytes
from bytecrypt import encrypt_directory
from bytecrypt import encrypt_file
from bytecrypt import decrypt_file
from bytecrypt import encrypt_string
from argparse import ArgumentParser
import sys

test_password = b"test123"
test_content = b"very secret thing"



def init_argparse() -> ArgumentParser:
    parser = ArgumentParser(
        prog="Bytecrypt",
        description="Easy data encryption / decryption"
    )
    parser.add_argument('-e', '--encrypt', action='store_true')
    parser.add_argument('-d', '--decrypt', action='store_true')
    parser.add_argument('-f', '--file')
    parser.add_argument('-dir', '--directory')
    parser.add_argument('-str', '--string')
    parser.add_argument('-p', '--password', required=True)
    return parser


def process_encrypting(args):
    if (args.directory and not args.file and not args.string):
        encrypt_directory(args.directory, test_password)
    elif (args.file and not args.directory and not args.string):
        encrypt_file(args.file, test_password)
    elif (args.string and not args.directory and not args.file):
        encrypt_string(args.string, test_password)
    else:
        print("\nWarning: passed more than one data argument (-dir, -file, -str)")


def process_decrypting(args):
    if (args.directory and not args.file and not args.string):
        pass
    elif (args.file and not args.directory and not args.string):
        decrypt_file(args.file, test_password)
    elif (args.string and not args.directory and not args.file):
        pass
    else:
        print("\nWarning: passed more than one data argument (-dir, -file, -str)")



def main():

    parser = init_argparse()

    args = parser.parse_args()
    print(args)

    if (args.encrypt and not args.decrypt):
        process_encrypting(args)
    elif (args.decrypt and not args.encrypt):
        process_decrypting(args)
    else:
        print("\nWarning: passed both encrypt and decrypt flags.")

    ### TODO
    ## command line arguments
    # -e    || --encrypt
    # -d    || --decrypt
    # -dir  || --directory
    # -r    || --recursive  (loops thru all dirs)
    # -str  || --string
    # -p    || --password

    ## encrypt/decrypt files
    # python -m bytecrypt -encrypt -file "test_file.txt" -password "test123"
    # python -m bytecrypt -encrypt -file ["test_file.txt", "secret.txt"] -password "test123"
    # python -m bytecrypt -decrypt -file ["tYWHbf_...2dHSL="] -password "test123"

    ## encrypt/decrypt string
    # python -m bytecrypt -encrypt -string "test_string-1234" -password "test123"
    # python -m bytecrypt -decrypt -string "tYWHbf_...2dHSL=" -password "test123"

    ## encrypt/decrypt directory
    # python -m bytecrypt -encrypt -dir ["test/directory1", "testdir2"] -password "test123"
    # python -m bytecrypt -decrypt -dir ["tYWHbf_...2dHSL="] -password "test123"
    # python -m bytecrypt -encrypt -dir . -password "test123"

    # arg_content = sys.argv[1]
    # arg_pass = sys.argv[2]
    # arg_content_bytes = bytes(arg_content, encoding="utf-8")
    # arg_pass_bytes = bytes(arg_pass, encoding="utf-8")
    # encrypted_content = encrypt_bytes(arg_content_bytes, arg_pass_bytes)
    #print("Cmd arg encrypted: " + arg_content + " -> " + str(encrypted_content.decode("utf-8")))

    # example = encrypt_bytes(test_content, test_password)
    # print("\nEncrypted thing: " + str(example.decode("unicode_escape")))
    # example = decrypt_bytes(example, test_password)
    # print("\nDecrypted thing: " + str(example.decode("utf-8")))

    # test_bytes = b"p0CuT_UD_L7a6efqgAAAAABnO91ptEsJa2R5AeWdbccPP-ASEAQp0IRD8_32Inry_J1OGRUNBaGzPbkxLYhUkQee_qYhLkDR7Tc1Id0W2SIyJejMJz2le0Pql5jKGAARH2FZkCs="
    # decrypted_bytes = decrypt_bytes(test_bytes, test_password)
    # print("\n\nDecrypted bytes: " + str(decrypted_bytes.decode("utf-8")))

if __name__ == "__main__":
    main()

