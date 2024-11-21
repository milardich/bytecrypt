import tomllib
import os
import sys


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

def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS 
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Example usage
pyproject_path = get_resource_path("pyproject.toml")


with open(pyproject_path, "rb") as f:
    data = tomllib.load(f)
    

__version__ = data['project']['version']
print("\nversion: " + str(__version__))


def get_version():
    return str(__version__)