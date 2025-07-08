import argparse
import os
from src.manager import PasswordManager
from src.encrypt import generate_key
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def main():
    parser = argparse.ArgumentParser(description="Password Cube Manager")
    parser.add_argument("action", choices=["insert", "delete", "edit", "list"],
                        help="Action to perform: insert, delete, edit, or list credentials")
    parser.add_argument("--username", help="Username for insert/edit")
    parser.add_argument("--password", help="Password for insert/edit")
    parser.add_argument("--position", nargs=3, type=int, help="Position in cube (x y z)")
    parser.add_argument("--key", required=True, help="Encryption key")

    args = parser.parse_args()

    cube_file = "data/cube.json"
    salt_file = "data/salt.bin"
    key, salt = generate_key(args.key.encode())
    if os.path.exists(salt_file):
        with open(salt_file, "rb") as f:
            salt = f.read()
        key, _ = generate_key(args.key.encode(), salt)
    else:
        with open(salt_file, "wb") as f:
            f.write(salt)
    manager = PasswordManager(key)

    if os.path.exists(cube_file):
        try:
            with open(cube_file, "rb") as f:
                encrypted_data = f.read()
                if not encrypted_data:
                    print("Error: cube.json is empty")
                    return
                manager.load_cube(encrypted_data)
            print("Loaded existing cube.")
        except Exception as e:
            print(f"Error loading cube: {type(e).__name__}: {str(e)}")
            return

    try:
        if args.action == "insert":
            if not (args.username and args.password and args.position):
                parser.error("insert requires --username, --password, and --position")
            position = tuple(args.position)
            manager.insert_credential(args.username, args.password, position)
            print(f"Inserted credential at {position}")
            print(f"Post-insert cube[0, 0, 0]: {manager.cube.cube[0, 0, 0]}")  # Debug

        elif args.action == "delete":
            if not args.position:
                parser.error("delete requires --position")
            position = tuple(args.position)
            manager.delete_credential(position)
            print(f"Deleted credential at {position}")

        elif args.action == "edit":
            if not args.position:
                parser.error("edit requires --position")
            if not (args.username or args.password):
                parser.error("edit requires at least one of --username or --password")
            position = tuple(args.position)
            manager.edit_credential(position, args.username, args.password)
            print(f"Edited credential at {position}")

        elif args.action == "list":
            credentials = manager.list_credentials()
            if credentials:
                for pos, cred in credentials:
                    print(f"Position {pos}: {cred}")
            else:
                print("No credentials found in the cube.")

        os.makedirs("data", exist_ok=True)
        encrypted_data = manager.save_cube()
        with open(cube_file, "wb") as f:
            f.write(encrypted_data)
        with open(salt_file, "wb") as f:
            f.write(salt)
        print("Cube and salt saved successfully!")

    except ValueError as e:
        print(f"ValueError: {e}")
    except Exception as e:
        print(f"Unexpected error: {type(e).__name__}: {str(e)}")

if __name__ == "__main__":
    main()