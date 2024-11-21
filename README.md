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

# files in directory
encrypt_directory("path/to/directory", b"testPassword")
decrypt_directory("path/to/directory", b"testPassword")


```

#### Example 3 - command line usage


```sh

# encrypt/decrypt files
python -m bytecrypt -e -f "test_file.txt" -p "test123"

# encrypt/decrypt string
python -m bytecrypt -e -str "test_string-1234" -p "test123"
python -m bytecrypt -d -str "tYWHbf_...2dHSL=" -p "test123"

# encrypt/decrypt files in directory
python -m bytecrypt -e -dir "test/directory1" -p "test123"
python -m bytecrypt -d -dir "test/directory1" -p "test123"
python -m bytecrypt -e -dir . -p "test123"

```

#### Command line arguments:


```sh

-e    ;    --encrypt
-d    ;    --decrypt
-f    ;    --file
-dir  ;    --directory
-str  ;    --string
-p    ;    --password

```
