import unittest
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.manager import PasswordManager
from src.encrypt import generate_key

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        """Clear any existing cube.json and salt.bin before each test."""
        cube_file = "data/cube.json"
        salt_file = "data/salt.bin"
        if os.path.exists(cube_file):
            os.remove(cube_file)
        if os.path.exists(salt_file):
            os.remove(salt_file)

    def test_insert_and_save(self):
        # Generate key and salt (device-bound)
        key, salt = generate_key("testkey1234567890".encode())
        manager = PasswordManager(key)
        
        # Insert a credential
        manager.insert_credential("b+5R6E21H7H7", "gY2E\!b4649!", (0, 0, 0))
        self.assertEqual(
            manager.cube.cube[0, 0, 0],
            {"username": "b+5R6E21H7H7", "password": "gY2E\!b4649!"}
        )
        
        # Save the cube
        encrypted_data = manager.save_cube()
        self.assertIsNotNone(encrypted_data)
        
        # Create a new manager and load the cube (on the same device)
        manager = PasswordManager(key)
        manager.load_cube(encrypted_data)
        self.assertEqual(
            manager.cube.cube[0, 0, 0],
            {"username": "b+5R6E21H7H7", "password": "gY2E\!b4649!"}
        )

if __name__ == "__main__":
    unittest.main()