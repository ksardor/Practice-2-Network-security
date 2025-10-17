# GPG Lowercase Passphrase Brute-Forcer

## Summary
This repository contains a Python program that attempts to recover a passphrase for a GPG-encrypted file (`.gpg`) when the passphrase is known to contain **lowercase letters only**.

**Warning:** Use only on files you own or for which you have explicit authorization to attempt passphrase recovery.

## Files
- `brute_force_gpg.py` — main brute-force script (see usage below).
- `README.md` — this file.
- `found.txt` — (output) if passphrase found, it's written here.
- `bf_checkpoint.json` — checkpoint file to resume long runs.

## Requirements
- GNU/Linux (tested on Ubuntu / Debian)
- Python 3.8+
- `gpg` (GnuPG) installed and in PATH
- Sufficient CPU cores / time for the chosen search space

Install gpg on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install gnupg
