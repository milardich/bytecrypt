from bytecrypt.bytecrypt import encrypt_bytes
from bytecrypt.bytecrypt import decrypt_bytes

test_password = b"test123"
test_content = b"very secret thing"

def main():

    # TODO: add command line arguments check

    example = encrypt_bytes(test_content, test_password)
    print("\nEncrypted thing: " + str(example.decode("unicode_escape")))
    example = decrypt_bytes(example, test_password)
    print("\nDecrypted thing: " + str(example.decode("utf-8")))

    test_bytes = b"PMQFLWQBO85NCRG6gAAAAABnO9hHaHXvqO9H9bjQWsKEViS4XVqXquz09mMSrDsxoyZ8FLq-JHysMkUvMoVFFGJdclm4NLBf_Eq4ilJy2fIFqlh4mrQhNxu36iwUAKMCIKR-bts="
    test2 = decrypt_bytes(test_bytes, test_password)
    print("\n\nIt should work now: " + str(test2.decode("utf-8")))

if __name__ == "__main__":
    main()