# 3D Cube Password Manager (GATE)

A password manager that stores credentials in a 3D cube of configurable size (default is 5x5x5, but you can create larger or smaller cubes as needed). The cube is encrypted with AES-256-GCM and bound to the user's device using a Machine GUID. The cube is scrambled with key-based rotations for added obfuscation, and cryptographic keys are derived using Argon2 for strong protection against brute-force attacks.

---

## Features

- **Strong cryptography:** Argon2 (memory-hard key derivation) and AES-256-GCM (128-bit quantum security)
- **Device-bound encryption:** Uses the Windows Machine GUID, so the cube is only decryptable on the original device
- **Configurable credential storage:** Credentials are stored in a 3D NumPy array (cube) of any size you choose (e.g., 5x5x5 by default, but can be larger or smaller)
- **Cube scrambling:** Key-based rotations to hide credential positions
- **Command-line interface:** Insert, delete, edit, and list credentials
- **Secure storage:** Encrypted cube (`data/cube.json`) and public salt (`data/salt.bin`)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows OS (for Machine GUID-based device binding)
- Git (optional, for cloning)

### Setup

1. Clone the repository:

    ```sh
    git clone https://github.com/your-username/cube-password-manager.git
    ```

2. Install dependencies:

    ```sh
    pip install -r requirements.txt
    ```

**Dependencies (`requirements.txt`):**
- cryptography>=3.4.8
- numpy>=1.21.0
- argon2-cffi>=21.3.0

---

## Usage

The password manager uses a command-line interface (`cli.py` in the project root). All commands require a `--key` passcode to derive the device-bound encryption key.

### Commands

```sh
python cli.py {insert,delete,edit,list} [options]
```

**Options:**
- `--username USERNAME`   Username for insert/edit
- `--password PASSWORD`   Password for insert/edit
- `--position x y z`      Cube position (e.g., 1 2 3)
- `--key KEY`             Encryption key (required)

### Examples

Insert a credential:
```sh
python cli.py insert --username alice --password secret --position 1 2 3 --key "yourpasscode"
```

List all credentials:
```sh
python cli.py list --key "yourpasscode"
```

### Notes

- The cube is saved to `data/cube.json` (encrypted) and `data/salt.bin` (public salt) after each operation.
- The salt is generated once and reused for all future operations. **Do not delete or modify `data/salt.bin` or you will lose access to your cube.**
- Use single quotes for passwords with special characters in PowerShell (e.g., `'%¤#%&'`).
- The `--key` passcode must be consistent to derive the same device-bound key.
- The CLI is located at `cli.py` in the project root (not in a `scripts/` folder).

---

## Security

### Cryptography
- **Argon2** is used for key derivation, making brute-force attacks (including quantum) more difficult.
- **AES-256-GCM** provides authenticated encryption; with quantum attacks, effective security is 128 bits.
- **Note:** No cryptography is truly "quantum-proof," but this manager uses strong, modern algorithms.

### Device Binding
- The key is derived from the passcode and Machine GUID, locking the cube to the original device.
- **Warning:** System reinstallation or Machine GUID changes may render the cube inaccessible without a key backup.

### Best Practices
- Use a high-entropy passcode (20+ random characters, >80 bits of entropy).
- Backup the passcode and/or Machine GUID securely to avoid lockout.
- Use a private repository if including `data/cube.json` or `data/salt.bin`.

### Troubleshooting

- If you lose or overwrite `data/salt.bin`, you will not be able to decrypt your cube.
- If you forget your passcode or your Machine GUID changes, you will lose access to your credentials.
- If you see decryption errors, check that you are using the correct passcode and that `data/salt.bin` is unchanged.

---

## Testing

Unit tests are provided for the cube logic. Run them with:

```sh
python -m unittest tests/test_cube.py
```

---

## Contributing

Sonny Holman (Developer)

---

## Contact

Email: sonnyholman@hotmail.com