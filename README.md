### About
Bytecrypt is a python package for easy data encryption / decryption with password.

### Installation
```sh

pip install bytecrypt

```

### Usage

#### Example 1

```py

# main.py

from bytecrypt import *

# byte array
encrypted_data = encrypt_bytes(b"secret", b"password")
decrypted_data = decrypt_bytes(encrypted_data, b"password")

print("\nEncrypted data: " + str(encrypted_data.decode("utf-8")))
print("\nDecrypted data: " + str(decrypted_data.decode("utf-8")))

```

```sh
# output

$ python main.py

Encrypted data: gAAAAABnO7wzHm-WLv-s_fQgHRe_-0Al_CmzUU7XfZcRaRSBXbLy1j8Z97KhiY8nZbaHETyKSO_NuGQH1f73MMs58nrT7pxWJg==

Decrypted data: secret


```

#### Example 2 - encrypting / decrypting file contents


```py
# files
encrypt_file("path/to/file/test.docx", b"testPassword")
decrypt_file("path/to/file/test.docx", b"testPassword")

encrypt_file("path/to/file/test.docx", b"testPassword", encrypt_filename=True)
decrypt_file("path/to/file/test.docx", b"testPassword", decrypt_filename=True)

# files in directory
encrypt_directory("path/to/directory", b"testPassword")
decrypt_directory("path/to/directory", b"testPassword")

encrypt_directory("path/to/directory", b"testPassword", encrypt_filename=True)
decrypt_directory("path/to/directory", b"testPassword", decrypt_filename=True)


```

#### Example 3 - command line usage


```sh

# encrypt file contents
bytecrypt -e -f "test_file.txt" -p "test123"

# decrypt file contents
bytecrypt -d -f "test_file.txt" -p "test123"

# encrypt file name and its contents
bytecrypt -e -f "test_file.txt" -efn -p "test123"

# decrypt file name and its contents
bytecrypt -d -f "EJHF2_1bf...FHJ=" -dfn -p "test123"

# encrypt/decrypt string
bytecrypt -e -str "test_string-1234" -p "test123"
bytecrypt -d -str "tYWHbf_...2dHSL=" -p "test123"

# encrypt/decrypt files in directory
bytecrypt -e -dir "test/directory1" -p "test123"
bytecrypt -d -dir "test/directory1" -p "test123"
bytecrypt -e -dir . -p "test123"
bytecrypt -e -dir . -p -efn "test123"
bytecrypt -d -dir . -p -dfn "test123"

# encrypt all directories inside of a directory (recursive)
bytecrypt -e -dir "test/directory1" -r -p "test123"

```

#### Command line arguments:


```sh

-e      ;   --encrypt
-d      ;   --decrypt
-f      ;   --file
-dir    ;   --directory
-efn    ;   --encrypt_filename
-dfn    ;   --decrypt_filename
-str    ;   --string
-r      ;   --recursive
-p      ;   --password

```
