import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import unittest
from cryptography.fernet import Fernet, InvalidToken
from src.encrypt import generate_key, encrypt_data, decrypt_data

class TestEncryption(unittest.TestCase):
    def setUp(self):
        """Set up test cases with a sample password and data."""
        self.password = "securepassword123"
        self.data = "Hello, World!"
        self.key = generate_key(self.password)

    def test_generate_key(self):
        """Test that generate_key produces a valid Fernet key."""
        key = generate_key(self.password)
        self.assertEqual(len(key), 44)  # Base64-encoded 32-byte key length
        self.assertIsInstance(key, bytes)  # Key should be bytes
        try:
            Fernet(key)  # Ensure the key is valid for Fernet
        except Exception:
            self.fail("Generated key is not valid for Fernet")

    def test_encrypt_decrypt_cycle(self):
        """Test that data can be encrypted and decrypted correctly."""
        encrypted = encrypt_data(self.data, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(self.data, decrypted)

    def test_encrypt_different_keys(self):
        """Test that encrypting with different passwords produces different outputs."""
        key2 = generate_key("differentpassword")
        encrypted1 = encrypt_data(self.data, self.key)
        encrypted2 = encrypt_data(self.data, key2)
        self.assertNotEqual(encrypted1, encrypted2)

    def test_decrypt_wrong_key(self):
        """Test that decrypting with the wrong key raises InvalidToken."""
        wrong_key = generate_key("wrongpassword")
        encrypted = encrypt_data(self.data, self.key)
        with self.assertRaises(InvalidToken):
            decrypt_data(encrypted, wrong_key)

    def test_empty_data(self):
        """Test encryption and decryption with empty data."""
        empty_data = ""
        encrypted = encrypt_data(empty_data, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(empty_data, decrypted)

    def test_special_characters(self):
        """Test encryption and decryption with special characters."""
        special_data = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        encrypted = encrypt_data(special_data, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(special_data, decrypted)

    def test_invalid_key_format(self):
        """Test that an invalid key format raises an exception."""
        invalid_key = b"invalid_key"  # Not a valid base64-encoded 32-byte key
        with self.assertRaises(ValueError):
            encrypt_data(self.data, invalid_key)

if __name__ == '__main__':
    unittest.main()