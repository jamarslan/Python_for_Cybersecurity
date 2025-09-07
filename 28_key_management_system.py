import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

KEY_FILE = "key_vault.json"  # File where keys will be saved

def generate_key():
    """Generate a random AES key (128-bit)."""
    key = get_random_bytes(16)  # AES 128-bit key
    print(f"Generated key: {key.hex()}")
    return key

def save_key(key):
    """Save the key to the key vault file in a secure manner."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as f:
            vault = json.load(f)
    else:
        vault = {}

    # Store the new key securely (simulate encrypted storage for simplicity)
    key_id = len(vault) + 1
    vault[key_id] = key.hex()

    with open(KEY_FILE, 'w') as f:
        json.dump(vault, f, indent=2)

    print(f"Key saved with ID: {key_id}")

def retrieve_key(key_id):
    """Retrieve a stored key from the key vault."""
    if not os.path.exists(KEY_FILE):
        print("[!] No keys found.")
        return None

    with open(KEY_FILE, 'r') as f:
        vault = json.load(f)

    if key_id in vault:
        key = bytes.fromhex(vault[key_id])
        print(f"Key retrieved: {key.hex()}")
        return key
    else:
        print(f"[!] Key ID {key_id} not found.")
        return None

def encrypt_data(data, key):
    """Encrypt data using AES (ECB mode)."""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = data + b' ' * (16 - len(data) % 16)  # Ensure data is multiple of 16
    encrypted = cipher.encrypt(padded_data)
    return encrypted

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES (ECB mode)."""
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted.rstrip()  # Remove padding

if __name__ == "__main__":
    action = input("Choose action (generate/save/retrieve/encrypt/decrypt): ").strip().lower()

    if action == "generate":
        key = generate_key()
        save_key(key)

    elif action == "save":
        key = generate_key()
        save_key(key)

    elif action == "retrieve":
        key_id = int(input("Enter key ID to retrieve: "))
        key = retrieve_key(key_id)
        if key:
            print(f"Key {key_id} retrieved successfully.")

    elif action == "encrypt":
        key_id = int(input("Enter key ID for encryption: "))
        key = retrieve_key(key_id)
        if key:
            data = input("Enter data to encrypt: ").encode()
            encrypted_data = encrypt_data(data, key)
            print(f"Encrypted data: {encrypted_data.hex()}")

    elif action == "decrypt":
        key_id = int(input("Enter key ID for decryption: "))
        key = retrieve_key(key_id)
        if key:
            encrypted_data = bytes.fromhex(input("Enter encrypted data to decrypt: "))
            decrypted_data = decrypt_data(encrypted_data, key)
            print(f"Decrypted data: {decrypted_data.decode()}")
    else:
        print("[!] Invalid action.")
