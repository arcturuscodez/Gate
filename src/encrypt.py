from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import argon2
from argon2.exceptions import HashingError
import winreg

def get_machine_guid():
    """Retrieve the Machine GUID from the Windows registry."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        )
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return guid.encode('utf-8') # Convert to bytes
    
    except Exception as e:
        raise ValueError(f"Failed to retrieve Machine GUID: {e}")

def generate_key(password, salt=None):
    """Generate a 32-byte key for AES-256 using Argon2, bound to the device."""
    if salt is None:
        salt = os.urandom(16)  # Random 16-byte salt
    try:
        # Combine password and Machine GUID for device binding
        machine_guid = get_machine_guid()
        combined_input = password + machine_guid
        
        # Use Argon2id with custom salt
        key = argon2.low_level.hash_secret_raw(
            secret=combined_input,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=argon2.low_level.Type.ID
        )
        return key, salt
    except HashingError as e:
        raise ValueError(f"Key generation failed: {e}")

def encrypt_data(data, key):
    """Encrypt data using AES-256-GCM."""
    iv = os.urandom(12)  # 12-byte IV for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-256-GCM."""
    if len(encrypted_data) < 28:  # IV (12) + tag (16)
        raise ValueError("Invalid encrypted data")
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()