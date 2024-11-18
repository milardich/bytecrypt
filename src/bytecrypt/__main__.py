from bytecrypt.bytecrypt import encrypt_bytes
from bytecrypt.bytecrypt import decrypt_bytes

test_password = b"test123"
test_content = b"very secret thing"

def main():

    # TODO: add command line arguments check

    example = encrypt_bytes(test_content, test_password)
    print("\nEncrypted thing: " + str(example.decode("utf-8")))
    example = decrypt_bytes(example, test_password)
    print("\nDecrypted thing: " + str(example.decode("utf-8")))

if __name__ == "__main__":
    main()