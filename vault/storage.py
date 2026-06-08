import json
import os
import platform
import stat
from pathlib import Path
from vault.trie import Trie

IS_WINDOWS = platform.system() == "Windows"
VAULT_FILE = Path(".vault.db")

def _read_vault() -> dict:

    if not VAULT_FILE.exists():
        return {}
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def _write_vault(data: dict) -> None:
    
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    if not IS_WINDOWS:
        os.chmod(VAULT_FILE, 0o600)

def build_trie_from_vault() -> Trie:

    trie = Trie()
    for key in _read_vault().keys():
        trie.insert(key)
    return trie

def vault_exists() -> bool:

    return VAULT_FILE.exists()

def set_secret(key: str, encrypted_blob: dict) -> None:

    data = _read_vault()
    data[key.upper()] = encrypted_blob
    _write_vault(data)


def get_secret(key: str) -> dict | None:

    data = _read_vault()
    return data.get(key.upper())


def delete_secret(key: str) -> bool:

    data = _read_vault()
    normalized = key.upper()
    if normalized not in data:
        return False
    del data[normalized]
    _write_vault(data)
    return True


def list_keys() -> list[str]:

    return sorted(_read_vault().keys())


def search_keys(prefix: str) -> list[str]:

    trie = build_trie_from_vault()
    return trie.search(prefix)


def check_vault_permissions() -> str | None:
    
    if not VAULT_FILE.exists():
        return None
    
    if IS_WINDOWS:
        return None

    mode = stat.S_IMODE(os.stat(VAULT_FILE).st_mode)
    if mode & 0o077:
        octal = oct(mode)
        return (
            f"  ⚠ WARNING: .vault.db has unsafe permissions ({octal}).\n"
            f"    Anyone on this machine may be able to read your encrypted secrets.\n"
            f"    Fix it immediately:  chmod 600 .vault.db"
        )
    return None