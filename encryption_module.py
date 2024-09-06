
from cryptography.fernet import Fernet
import time

# Generate initial encryption key
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Function to encrypt data
def encrypt_data(data):
    return cipher_suite.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

# Key rotation function
def rotate_encryption_key(current_encrypted_data):
    global cipher_suite  # Ensure you're updating the global cipher suite

    # Decrypt the current data using the old key
    decrypted_data = decrypt_data(current_encrypted_data)

    # Generate a new encryption key
    new_key = Fernet.generate_key()
    new_cipher_suite = Fernet(new_key)

    # Re-encrypt the data with the new key
    re_encrypted_data = new_cipher_suite.encrypt(decrypted_data.encode()).decode()

    # Replace the old cipher suite with the new one
    cipher_suite = new_cipher_suite

    # Optionally, store the new key securely and archive the old key
    store_new_key(new_key)
    
    return re_encrypted_data

def store_new_key(new_key):
    # You can implement logic to securely store the new key (e.g., in a file, database, or key vault)
    with open('encryption_keys.txt', 'a') as key_file:
        key_file.write(f"{new_key.decode()} - {time.ctime()}
")
