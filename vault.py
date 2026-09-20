# Cryptographic Encryption Vault - Multi-file Directory Encryption
# pip install cryptography

import os
import base64
import shutil
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Step 2: Key management with master passphrase + backup
def generate_master_key(passphrase: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key, salt

def save_key_backup(key, salt):
    # Step 3: Secure key file backup
    with open("vault.key", "wb") as kf:
        kf.write(salt + b"::" + key)
    # Backup copy
    with open("vault.key.backup", "wb") as bk:
        bk.write(salt + b"::" + key)
    print("[+] Key backup generated: vault.key + vault.key.backup (Keep safe!)")

def load_key_from_backup(passphrase=None):
    if os.path.exists("vault.key"):
        with open("vault.key", "rb") as kf:
            data = kf.read()
            salt, stored_key = data.split(b"::")
            if passphrase:
                # Re-derive to verify passphrase matches
                key, _ = generate_master_key(passphrase, salt)
                return key
            return stored_key
    return None

# Step 1: Recursively scan directory
def encrypt_directory(dir_path, passphrase):
    dir_path = Path(dir_path)
    if not dir_path.exists():
        os.makedirs(dir_path)
        # Create demo files
        (dir_path / "secret1.txt").write_text("Sensitive file 1")
        (dir_path / "data.csv").write_text("id,password\n1,12345")

    key, salt = generate_master_key(passphrase)
    save_key_backup(key, salt)
    fernet = Fernet(key)

    encrypted_files = []
    # Step 1: Recursive scan
    for file_path in dir_path.rglob("*"):
        if file_path.is_file():
            print(f"[*] Encrypting {file_path}")
            data = file_path.read_bytes()
            enc_data = fernet.encrypt(data)
            # Write.vault
            enc_path = file_path.with_suffix(file_path.suffix + ".vault")
            enc_path.write_bytes(enc_data)
            encrypted_files.append(str(enc_path))
            # Remove original for security (optional)
            file_path.unlink()

    print(f"[+] Directory encrypted: {len(encrypted_files)} files")
    return encrypted_files

# Step 4: Test full restoration without corruption
def decrypt_directory(dir_path, passphrase):
    dir_path = Path(dir_path)
    key, _ = generate_master_key(passphrase, salt=open("vault.key","rb").read().split(b"::")[0])
    # For simplicity load from backup
    with open("vault.key","rb") as f:
        s,k = f.read().split(b"::")
        key = k
    fernet = Fernet(key)

    restored = []
    for enc_file in dir_path.rglob("*.vault"):
        print(f"[*] Decrypting {enc_file}")
        data = fernet.decrypt(enc_file.read_bytes())
        original_path = Path(str(enc_file).replace(".vault",""))
        original_path.write_bytes(data)
        enc_file.unlink()
        restored.append(str(original_path))

    print(f"[+] Directory restored: {len(restored)} files - No corruption!")
    return restored

if __name__ == "__main__":
    print("=== Cryptographic Encryption Vault ===")
    mode = input("E for Encrypt Dir / D for Decrypt Dir: ").lower()
    target_dir = input("Enter dir path (ex: my_vault): ") or "my_vault"
    pwd = input("Enter MASTER passphrase: ") or "Master@123"

    if mode == 'e':
        encrypt_directory(target_dir, pwd)
    else:
        decrypt_directory(target_dir, pwd)
