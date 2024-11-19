from bytecrypt import encrypt_bytes
from bytecrypt import decrypt_bytes
import sys

test_password = b"test123"
test_content = b"very secret thing"

def main():

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

    example = encrypt_bytes(test_content, test_password)
    print("\nEncrypted thing: " + str(example.decode("unicode_escape")))
    example = decrypt_bytes(example, test_password)
    print("\nDecrypted thing: " + str(example.decode("utf-8")))

    test_bytes = b"p0CuT_UD_L7a6efqgAAAAABnO91ptEsJa2R5AeWdbccPP-ASEAQp0IRD8_32Inry_J1OGRUNBaGzPbkxLYhUkQee_qYhLkDR7Tc1Id0W2SIyJejMJz2le0Pql5jKGAARH2FZkCs="
    decrypted_bytes = decrypt_bytes(test_bytes, test_password)
    print("\n\nDecrypted bytes: " + str(decrypted_bytes.decode("utf-8")))

if __name__ == "__main__":
    main()