import base64
import os
import random
import string
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
import winreg
import time

class QuantumResistantEncryption:
    def __init__(self, password):
        self.password = password
        self.machine_guid = self.get_machine_guid()
        self.salt = os.urandom(16)  # Random 16-byte salt for entropy
        self.rsa_private_key, self.rsa_public_key = self.generate_rsa_keypair()

    def get_machine_guid(self):
        """Retrieve the Machine GUID from the Windows registry."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            )
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            return guid.encode('utf-8')  # Convert to bytes
        
        except Exception as e:
            raise ValueError(f"Failed to retrieve Machine GUID: {e}")

    def generate_rsa_keypair(self):
        """Generate RSA key pair for hybrid encryption."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_rsa(self, plaintext):
        """Encrypt plaintext using RSA public key."""
        ciphertext = self.rsa_public_key.encrypt(
            plaintext.encode(),
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_rsa(self, ciphertext):
        """Decrypt ciphertext using RSA private key."""
        plaintext = self.rsa_private_key.decrypt(
            ciphertext,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def generate_key(self):
        """Generate a hybrid key by combining password and machine GUID with entropy."""
        combined_input = self.password.encode() + self.machine_guid + self.salt
        key = hashlib.sha256(combined_input).digest()
        return key

    def encrypt_data(self, data):
        """Encrypt data using AES-GCM with the hybrid key."""
        key = self.generate_key()
        iv = os.urandom(12)  # 12-byte IV for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt_data(self, encrypted_data):
        """Decrypt data using AES-GCM and the hybrid key."""
        if len(encrypted_data) < 28:  # IV (12) + tag (16)
            raise ValueError("Invalid encrypted data")
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        key = self.generate_key()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    def generate_entropy_key(self):
        """Generate a key based on system entropy (or other source)."""
        # Example of key generation from entropy or another source
        entropy = os.urandom(32)  # Example of entropy; make sure it's the same for both encryption and decryption
        print(f"Generated Key: {base64.b64encode(entropy)}")
        return entropy

    def encrypt_with_entropy(self, data):
        """Encrypt data using entropy-based AES-GCM."""
        entropy_key = self.generate_entropy_key()
        iv = os.urandom(12)  # 12-byte IV for AES-GCM
        cipher = Cipher(algorithms.AES(entropy_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

        # Debugging: print out components before concatenation
        print(f"IV (12 bytes): {base64.b64encode(iv)}")
        print(f"Tag (16 bytes): {base64.b64encode(encryptor.tag)}")
        print(f"Ciphertext: {base64.b64encode(ciphertext)}")

        # Concatenate IV, tag, and ciphertext
        return iv + encryptor.tag + ciphertext

    def decrypt_with_entropy(self, encrypted_data):
        """Decrypt data using entropy-based AES-GCM."""
        if len(encrypted_data) < 28:  # IV (12) + tag (16)
            raise ValueError("Invalid encrypted data")

        # Extract IV, tag, and ciphertext
        iv = encrypted_data[:12]  # First 12 bytes is the IV
        tag = encrypted_data[12:28]  # Next 16 bytes is the authentication tag
        ciphertext = encrypted_data[28:]  # The remaining bytes are the ciphertext

        # Debugging: print extracted components
        print(f"Extracted IV (12 bytes): {base64.b64encode(iv)}")
        print(f"Extracted Tag (16 bytes): {base64.b64encode(tag)}")
        print(f"Extracted Ciphertext: {base64.b64encode(ciphertext)}")

        # Ensure the key generation is the same for both encryption and decryption
        entropy_key = self.generate_entropy_key()
        print(f"Decryption Key: {base64.b64encode(entropy_key)}")  # Debugging: print the decryption key

        # Check if the generated entropy key matches the one used during encryption
        print(f"Generated Key: {base64.b64encode(self.generate_key())}")  # Ensure this is the same key

        # Setup AES-GCM cipher for decryption
        cipher = Cipher(algorithms.AES(entropy_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()

        try:
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"Decrypted Data: {decrypted_data.decode()}")
            return decrypted_data.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            raise ValueError(f"Decryption failed: {e}")
    
password = "mysecretpassword"

# Initialize encryption class
encryption = QuantumResistantEncryption(password)

# Encrypt data using RSA public key
plaintext = "This is a secret message."
encrypted_rsa = encryption.encrypt_rsa(plaintext)
print("Encrypted (RSA):", base64.b64encode(encrypted_rsa))

# Decrypt data using RSA private key
decrypted_rsa = encryption.decrypt_rsa(encrypted_rsa)
print("Decrypted (RSA):", decrypted_rsa)

# Encrypt data using AES-GCM with hybrid key
encrypted_data = encryption.encrypt_data(plaintext)
print("Encrypted (AES-GCM):", base64.b64encode(encrypted_data))

# Decrypt data using AES-GCM with hybrid key
decrypted_data = encryption.decrypt_data(encrypted_data)
print("Decrypted (AES-GCM):", decrypted_data)

# Encrypt data using entropy-based AES-GCM
encrypted_entropy_data = encryption.encrypt_with_entropy(plaintext)
print("Encrypted (Entropy):", base64.b64encode(encrypted_entropy_data))

# Decrypt data using entropy-based AES-GCM
decrypted_entropy_data = encryption.decrypt_with_entropy(encrypted_entropy_data)
print("Decrypted (Entropy):", decrypted_entropy_data)