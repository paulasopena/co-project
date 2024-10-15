import base64
from cryptography.fernet import Fernet


raw_key = b"445"
padded_key = raw_key.ljust(32, b'0')
key = base64.urlsafe_b64encode(padded_key)

print(f"Original base64-encoded key: {key}")

with open("pass.key", "wb") as key_file:
    key_file.write(key)

# Function to load the key from the file
def call_key():
    return open("pass.key", "rb").read()

# Retrieve the key from the file
key = call_key()

# Create Fernet object with the key
a = Fernet(key)

# Encrypt a message
message = b"Awesome code!!"
encrypted_message = a.encrypt(message)
print(f"Encrypted message: {encrypted_message}")

# Load the key again (if needed)
key = call_key()

# Create Fernet object again
b = Fernet(key)

# Decrypt the message
decrypted_message = b.decrypt(encrypted_message)
print(f"Decrypted message: {decrypted_message}")

# Check if the decrypted message matches the original message
if decrypted_message == message:
    print("Decryption successful. The decrypted message matches the original.")
else:
    print("Decryption failed. The decrypted message does not match the original.")
