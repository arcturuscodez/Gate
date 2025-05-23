from src.cube import Cube
from src.encrypt import encrypt_data, decrypt_data

class PasswordManager:
    
    def __init__(self, key):
        """Initialize the password manager with a key."""
        self.key = key  # Raw 32-byte key
        self.cube = Cube()

    def load_cube(self, encrypted_data):
        """Load and decrypt the cube from encrypted data."""
        decrypted_data = decrypt_data(encrypted_data, self.key)
        self.cube = Cube.from_json(decrypted_data)
        self.cube.unscramble(self.key)

    def save_cube(self):
        """Serialize, scramble, and encrypt the cube."""
        self.cube.scramble(self.key)
        json_data = self.cube.to_json()
        return encrypt_data(json_data, self.key)

    def insert_credential(self, username, password, position):
        """Insert a credential into the cube."""
        self.cube.insert(username, password, position)

    def delete_credential(self, position):
        """Delete a credential from the cube."""
        self.cube.delete(position)

    def edit_credential(self, position, new_username=None, new_password=None):
        """Edit a credential in the cube."""
        self.cube.edit(position, new_username, new_password)