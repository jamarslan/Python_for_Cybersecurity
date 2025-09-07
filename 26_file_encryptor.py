from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

BLOCK_SIZE = 16  # AES block size in bytes

def pad(data):
    """Pad data to a multiple of 16 bytes using PKCS7"""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove PKCS7 padding"""
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        data = f.read()

    padded_data = pad(data)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(padded_data)

    enc_file = file_path + ".enc"
    with open(enc_file, "wb") as f:
        f.write(encrypted)

    print(f"✅ File encrypted: {enc_file}")

def decrypt_file(enc_file_path, key):
    with open(enc_file_path, "rb") as f:
        encrypted = f.read()

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(encrypted)
    decrypted = unpad(decrypted_padded)

    dec_file = enc_file_path.replace(".enc", ".dec")
    with open(dec_file, "wb") as f:
        f.write(decrypted)

    print(f"✅ File decrypted: {dec_file}")

if __name__ == "__main__":
    choice = input("Encrypt or Decrypt? (E/D): ").strip().upper()
    file_path = input("Enter the file path: ").strip()

    # Use a 16-byte random key
    key = get_random_bytes(16)
    print(f"Using random key: {key.hex()} (keep this to decrypt!)")

    if choice == "E":
        encrypt_file(file_path, key)
    elif choice == "D":
        decrypt_file(file_path, key)
    else:
        print("[!] Invalid choice. Enter E or D.")
