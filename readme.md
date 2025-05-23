# 3D Cube Password Manager

A quantum-resistant password manager that stores credentials in a 5x5x5 cube, encrypted with AES-256-GCM and bound to the user's device using a Machine GUID. The cube is scrambled with key-based rotations for added obfuscation, and cryptographic keys are derived using Argon2 for protection against quantum computing threats.

## Features

- Quantum-resistant cryptography with Argon2 (memory-hard key derivation) and AES-256-GCM (128-bit quantum security)
- Device-bound encryption using the Windows Machine GUID, ensuring the cube is only decryptable on the original device
- Credential storage in a 5x5x5 NumPy array with (x, y, z) coordinates
- Cube scrambling with key-based rotations to hide credential positions
- Command-line interface for inserting, deleting, editing, and listing credentials
- Secure storage of encrypted cube (`data/cube.json`) and public salt (`data/salt.bin`)

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows OS (for Machine GUID-based device binding)
- Git (optional, for cloning)

### Setup

1. Clone the repository:

    git clone https://github.com/your-username/cube-password-manager.git

2. Install dependencies:

    pip install -r requirements.txt

Dependencies (`requirements.txt`):
- cryptography>=3.4.8
- numpy>=1.21.0
- argon2-cffi>=21.3.0

## Usage

The password manager uses a command-line interface (`scripts/cli.py`). All commands require a `--key` passcode to derive the device-bound encryption key.

### Commands

positional arguments:
  {insert,delete,edit,list}
                        Action to perform: insert, delete, edit, or list credentials

options:
  -h, --help            show this help message and exit
  --username USERNAME   Username for insert/edit
  --password PASSWORD   Password for insert/edit
  --position POSITION POSITION POSITION
                        Position in cube (x y z)
  --key KEY             Encryption key

### Notes

- The cube is saved to `data/cube.json` (encrypted) and `data/salt.bin` (public salt) after each operation.
- Use single quotes for passwords with special characters in PowerShell (e.g., `'%¤#%&'`).
- The `--key` passcode must be consistent to derive the same device-bound key.

## Security

### Quantum Resistance
- Argon2 resists quantum brute-forcing (Grover’s algorithm).
- AES-256-GCM provides 128-bit quantum security.
- Future enhancements could include post-quantum key exchange (e.g., Kyber).

### Device Binding
- The key is derived from the passcode and Machine GUID, locking the cube to the original device.
- **Warning**: System reinstallation or Machine GUID changes may render the cube inaccessible without a key backup.

### Best Practices
- Use a high-entropy passcode (20+ random characters, >80 bits of entropy).
- Backup the passcode and/or Machine GUID securely to avoid lockout.
- Use a private repository if including `data/cube.json` or `data/salt.bin`.

## Testing

Run unit tests to verify insertion, saving, loading, scrambling, and unscrambling:

python -m unittest tests/test_cube.py