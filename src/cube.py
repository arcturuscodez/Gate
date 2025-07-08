import json
import numpy as np
import hashlib

class Cube:
    def __init__(self, size=5):
        """Initialize a 3D cube with the given size."""
        self.size = size
        self.cube = np.full((size, size, size), None, dtype=object)

    def insert(self, username, password, position):
        """Insert a username and password at the specified position."""
        if not isinstance(position, tuple) or len(position) != 3:
            raise ValueError("Position must be a 3-tuple (x, y, z)")
        if not all(0 <= p < self.size for p in position):
            raise ValueError(f"Position {position} is out of bounds for cube of size {self.size}")
        x, y, z = position
        print(f"Inserting at {position}: {{'username': {username}, 'password': {password}}}")  # Debug
        self.cube[x, y, z] = {"username": username, "password": password}
        print(f"After insert, cube[{x}, {y}, {z}]: {self.cube[x, y, z]}")  # Debug

    def delete(self, position):
        """Delete the credential at the specified position."""
        if not isinstance(position, tuple) or len(position) != 3:
            raise ValueError("Position must be a 3-tuple (x, y, z)")
        if not all(0 <= p < self.size for p in position):
            raise ValueError(f"Position {position} is out of bounds for cube of size {self.size}")
        x, y, z = position
        self.cube[x, y, z] = None

    def edit(self, position, new_username=None, new_password=None):
        """Edit the credential at the specified position."""
        if not isinstance(position, tuple) or len(position) != 3:
            raise ValueError("Position must be a 3-tuple (x, y, z)")
        if not all(0 <= p < self.size for p in position):
            raise ValueError(f"Position {position} is out of bounds for cube of size {self.size}")
        x, y, z = position
        if self.cube[x, y, z] is None:
            raise ValueError("No credential exists at this position")
        credential = self.cube[x, y, z]
        if new_username:
            credential["username"] = new_username
        if new_password:
            credential["password"] = new_password

    def scramble(self, key):
        """Scramble the cube based on the key."""
        seed = int(hashlib.sha256(key).hexdigest(), 16) % 2**32
        np.random.seed(seed)
        for _ in range(3):
            axis = np.random.randint(0, 3)
            layer = np.random.randint(0, self.size)
            self.cube = np.rot90(self.cube, k=1, axes=(axis, (axis + 1) % 3))
        print("Cube scrambled")  # Debug

    def unscramble(self, key):
        """Unscramble the cube based on the key."""
        seed = int(hashlib.sha256(key).hexdigest(), 16) % 2**32
        np.random.seed(seed)
        rotations = [(np.random.randint(0, 3), np.random.randint(0, self.size)) for _ in range(3)]
        for axis, layer in reversed(rotations):
            self.cube = np.rot90(self.cube, k=-1, axes=(axis, (axis + 1) % 3))
        print("Cube unscrambled")  # Debug

    def to_json(self):
        """Serialize the cube to a JSON string."""
        return json.dumps(self.cube.tolist(), default=lambda x: x if x is not None else None)

    def list_credentials(self):
        """List all credentials in the cube."""
        creds = []
        for x in range(self.size):
            for y in range(self.size):
                for z in range(self.size):
                    val = self.cube[x, y, z]
                    if val is not None:
                        creds.append(((x, y, z), val))
        return creds

    @classmethod
    def from_json(cls, json_str):
        """Deserialize a cube from a JSON string."""
        cube_data = json.loads(json_str)
        cube = cls()
        cube.cube = np.array(cube_data, dtype=object)
        return cube