# File Protection Utility - AES-256 with PBKDF2
# pip install cryptography

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

# Step 2: Key derivation using PBKDF2 with salt
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Step 3: Encrypt target file into .enc
def encrypt_file(file_path, password):
    print(f"[*] Encrypting {file_path} with AES-256...")
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    # Save salt + encrypted data
    with open(file_path + ".enc", 'wb') as enc_file:
        enc_file.write(salt + encrypted_data)

    print(f"[+] Encrypted successfully -> {file_path}.enc")

# Step 4: Decrypt verifying MAC integrity
def decrypt_file(enc_file_path, password):
    print(f"[*] Decrypting {enc_file_path}...")
    try:
        with open(enc_file_path, 'rb') as f:
            content = f.read()

        salt = content[:16]
        encrypted_data = content[16:]

        key = generate_key(password, salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data) # Verifies MAC automatically

        original_path = enc_file_path.replace(".enc", ".decrypted.txt")
        with open(original_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        print(f"[+] Decryption successful, MAC verified! -> {original_path}")
        return True
    except InvalidToken:
        print("[!] FAILED: Wrong password or file tampered! MAC verification failed.")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

if __name__ == "__main__":
    print("=== File Protection Utility (AES-256 + PBKDF2) ===")
    mode = input("Enter E for Encrypt / D for Decrypt: ").lower()
    file = input("Enter file path (ex: secret.txt): ")
    pwd = input("Enter password: ")

    if mode == 'e':
        if not os.path.exists(file):
            # create dummy file for demo
            with open(file, 'w') as f: f.write("This is sensitive data")
        encrypt_file(file, pwd)
    else:
        decrypt_file(file, pwd)
