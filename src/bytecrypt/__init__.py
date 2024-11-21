import tomllib

from .bytecrypt import (
    encrypt_bytes, 
    decrypt_bytes, 
    encrypt_directory, 
    decrypt_directory,
    encrypt_file, 
    decrypt_file,
    encrypt_string,
    decrypt_string,
) 

__version__ = "0.0.0"
data = None

with open("../../pyproject.toml") as f:
    data = tomllib.load(f)

__version__ = data.get("version")