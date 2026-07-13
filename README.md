# 🌐 DotDB - CLI Secret Key Manager



A command-line tool for managing encrypted environment variables.

Built with PBKDF2 key derivation, AES-256-GCM encryption and a Trie data structure for prefix-based search.

---
Every developer has a `.env` file sitting in their project.

One accidental `git push` and those secrets are public forever.
This tool ensures secrets are encrypted before they ever touch disk.

## How Secrets Are Stored and Retrieved
 
### 🔒 Storing a Secret

When you run:
 
```bash
python -m vault.cli set DB_PASSWORD "Password@123"
```
 
Three things happen:
 
**1. Your value gets encrypted.**
The string `"Password@123"` is encrypted using AES-256-GCM. This produces three pieces of data — a salt, a nonce, and the ciphertext. None of these three pieces alone can recover your original value.
 
**2. The encrypted blob is written to `.vault.db`.**
The vault file is a JSON file that acts as a HashMap — the key name maps directly to its encrypted blob:
 
```json
{
  "DB_PASSWORD": {
    "salt": "a3f8b2c1d4e5f6a7...",
    "nonce": "f4a2b8c3d1e96f05...",
    "ciphertext": "9d4f2a1b8e3c7f2a..."
  }
}
```
 
The key name `DB_PASSWORD` is stored in plaintext — it is a label, not a secret. The value `"Password@123"` is what gets encrypted and is never visible in the file.
 
**3. The key name is inserted into an in-memory Trie.**
Every time a search or list operation runs, all key names are loaded from `.vault.db` into a Trie (prefix tree) in memory. This is what makes prefix-based search fast.
 
---
 
### 🔓 Retrieving a Secret
 
When you run:
 
```bash
python -m vault.cli get DB_PASSWORD
```
 
Two things happen:
 
**1. The encrypted blob is fetched from `.vault.db` by key name.**
This is a direct HashMap lookup with an O(1) average case. The salt, nonce, and ciphertext are read from the file.
 
**2. The blob is decrypted.**
Using the salt stored in the blob and your master password, the original AES key is re-derived. The ciphertext is then decrypted back to `"Password@123"`.
 
If the password is wrong, decryption fails immediately with an authentication error. The vault does not attempt a partial decrypt — it either fully succeeds or fully fails.
 
---
 
## Installation
 
```bash
git clone https://github.com/Anhad-Beri/cli-secret-manager.git
cd cli-secret-manager
pip install -e .
```

> ⚠️ **Important:** Always add `.vault.db` and `.vault.lock` to 
> your `.gitignore`. If accidentally committed, your secrets remain
> encrypted and unreadable without the master password which is never saved.
> Committing will not lead to your secret keys getting public, but it is
> reccommended as an extra measure. 
---
 
## Commands
 
### Initialize a vault
 
```bash
python -m vault.cli init
```
 
Creates `.vault.db` in the current directory. You will be prompted to set a master password. This password is never stored — do not forget it.
 
### 🔒 Store a secret
 
```bash
python -m vault.cli set KEY VALUE
```
 
Example:
```bash
python -m vault.cli set DB_PASSWORD "Password@123"
python -m vault.cli set AWS_SECRET "abc123"
```
 
### 🔓 Retrieve a secret
 
```bash
python -m vault.cli get KEY
```
 
Prints the decrypted value to the terminal. To copy to clipboard instead:
 
```bash
python -m vault.cli get KEY --clip
```
 
The clipboard is automatically cleared after 15 seconds.
 
### 🗝️ List all keys
 
```bash
python -m vault.cli list
```
 
Shows all stored key names. No decryption happens — values are never exposed during a list.
 
###  🔍 Search keys by prefix
 
```bash
python -m vault.cli search PREFIX
```
 
Example:
```bash
python -m vault.cli search DB_
```

### 🗑️ Delete a secret
 
```bash
python -m vault.cli delete KEY
```
### 🚀 Run a command with secrets injected

```bash
python -m vault.cli run -- COMMAND
```

Decrypts all secrets and injects them as environment variables
into the process. Your app accesses them via `os.getenv()` —
nothing is written to disk.

Example:
```bash
python -m vault.cli run -- python app.py
python -m vault.cli run -- bash deploy.sh
```

Inside `app.py`:
```python
import os
db_password = os.getenv("DB_PASSWORD")  # works exactly like .env
```

Secrets exist only in subprocess memory and vanish when it exits.
## Project Structure

```
vault/
├── crypto.py     # PBKDF2 key derivation + AES-256-GCM encrypt/decrypt
├── trie.py       # Prefix tree implemented from scratch
├── storage.py    # JSON HashMap persistence + file permission checks
├── lockout.py    # Brute-force protection
└── cli.py        # CLI — 6 commands
```

___

## The Master Password

The master password is the only thing that can decrypt your secrets.
It is never stored anywhere — not in `.vault.db`, not in a config
file, not in memory after the program exits.

**There is no forgot password feature. If you lose it, your 
encrypted secrets are permanently unreadable.**

When you store or retrieve a secret, your password is passed through
PBKDF2 (Password-Based Key Derivation Function 2) with 600,000
iterations of SHA-256. This produces a 256-bit AES key from your
human-readable password. 600,000 iterations means an attacker 
brute-forcing your password faces ~0.5 seconds per guess — making
a billion guesses take approximately 15 years.

-----

## Security Model

### What This Tool Protects Against

- Secrets committed to GitHub — `.vault.db` is encrypted and 
  unreadable without the master password
- Other users on the same machine — vault file permissions set 
  to owner read/write only on Unix
- Brute-force attacks — vault locks for 60 seconds after 5 wrong 
  password attempts
- Tampered vault files — AES-GCM authentication tag detects any 
  modification and fails immediately

### What This Tool Does Not Protect Against

- An attacker who already knows your master password
- OS-level keyloggers capturing your password as you type
- Secrets already loaded into process memory

### Why This Is Safer Than .env

| | `.env` file | CLI Secret Manager |
|---|---|---|
| Accidentally pushed to GitHub | Immediate breach | Secrets stay encrypted |
| Read by another user on same machine | Plaintext visible | Encrypted, unreadable |
| Brute-force protection | None | 60s lockout after 5 attempts |
| Master credential required | No | Yes |

## Limitations

- Single user only — no team vault support
- No key rotation — compromised master password requires 
  re-encrypting all secrets manually  
- Key names stored in plaintext — an attacker can see you have 
  a `DB_PASSWORD`, not what it is
- File permission enforcement is Unix only
