from bytecrypt import encrypt_bytes

test = encrypt_bytes(b"test", b"test")
print(str(test.decode("utf-8")))