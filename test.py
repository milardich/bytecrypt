from bytecrypt import encrypt_bytes, decrypt_bytes


f = open("tests/geming.xlsx", "r+b")

b = f.read()
print("\nOriginal hex:\t\t" + b.hex()[:16])
print("Original utf8:\t\t" + str(b[:16]))

e = encrypt_bytes(b, b"test123")
print("\nEncrypted hex:\t\t" + e.hex()[:16])
print("Encrypted utf8:\t\t" + str(e[:16]))

f.seek(0)
f.write(e)
f.truncate()

d = decrypt_bytes(e, b"test123")
print("\nDecrypted hex:\t\t" + d.hex()[:16])
print("Decrypted utf8:\t\t" + str(d[:16]))

f.seek(0)
f.write(d)
f.truncate()

# print("\nDecrypted hex:\t\t" + d.hex()[:16])
# print("\nDecrypted utf8:\t\t" + str(d[:16]))
# test = encrypt_bytes(b"test", b"test")
# print(str(test.decode("utf-8")))