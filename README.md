# Gecko

Encrypted USB vault. AES-256-GCM, pure C, no dependencies.

## Install

Download `gecko-x.x.x-setup-x64.exe` from [Releases](../../releases), run it, open a new terminal.

## Build from Source

```bash
cmake -B build
cmake --build build --config Release
```

Binaries in `build/bin/Release/`.

## Usage

```bash
gecko create vault.gko          # Create vault
gecko add vault.gko file.txt    # Add file
gecko add-expire vault.gko name file.txt 24  # Add with 24h expiration
gecko ls vault.gko              # List contents
gecko get vault.gko file.txt    # Extract file
gecko rm vault.gko file.txt     # Remove file
gecko versions vault.gko name   # List file versions
gecko restore vault.gko name 1  # Restore version
gecko info vault.gko            # Vault info
gecko passwd vault.gko          # Change password

gecko note vault.gko name       # Add encrypted note
gecko read vault.gko name       # Read note
gecko clip vault.gko name       # Save clipboard
gecko paste vault.gko name      # Restore clipboard

gecko shred file.txt            # Secure delete (3-pass)
gecko addshred vault.gko file   # Add then shred original

gecko hide vault.gko img.bmp    # Hide vault in image
gecko unhide img.bmp vault.gko  # Extract from image

gecko drives                    # List USB drives
gecko eject E:\                 # Safely eject
```

Emergency wipe: use password `WIPE:yourpassword` to destroy vault.

## Tests

```bash
./build/bin/Release/test_crypto
./build/bin/Release/test_vault
```
