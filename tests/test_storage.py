"""
Tests for the storage module.

Key challenge: storage.py uses hardcoded VAULT_FILE = Path(".vault.db").
We use monkeypatch to redirect it to tmp_path so tests never pollute
the real project directory.
"""

import os
import json
import platform
import pytest
import vault.storage as storage_mod

IS_WINDOWS = platform.system() == "Windows"


@pytest.fixture(autouse=True)
def redirect_vault_file(tmp_path, monkeypatch):
    """
    Redirect VAULT_FILE to a temp directory for every test automatically.
    Same pattern as test_lockout.py — monkeypatch restores original after each test.
    """
    monkeypatch.setattr(storage_mod, "VAULT_FILE", tmp_path / ".vault.db")


def _make_fake_blob(value="test_value"):
    """
    Return a fake encrypted blob dict.
    Storage tests don't care about real encryption — they just need
    a valid dict shape to store and retrieve.
    """
    return {"salt": "aabbcc", "nonce": "ddeeff", "ciphertext": value}


# ── set_secret / get_secret ────────────────────────────────────────────────────

def test_set_and_get_roundtrip():
    blob = _make_fake_blob()
    storage_mod.set_secret("DB_PASSWORD", blob)
    result = storage_mod.get_secret("DB_PASSWORD")
    assert result == blob


def test_get_missing_key_returns_none():
    result = storage_mod.get_secret("NONEXISTENT_KEY")
    assert result is None


def test_key_is_normalized_to_uppercase():
    blob = _make_fake_blob()
    storage_mod.set_secret("db_password", blob)
    assert storage_mod.get_secret("DB_PASSWORD") == blob
    assert storage_mod.get_secret("db_password") == blob


def test_set_overwrites_existing_key():
    storage_mod.set_secret("MY_KEY", _make_fake_blob("old"))
    storage_mod.set_secret("MY_KEY", _make_fake_blob("new"))
    result = storage_mod.get_secret("MY_KEY")
    assert result["ciphertext"] == "new"


def test_vault_file_created_on_first_set():
    assert not storage_mod.VAULT_FILE.exists()
    storage_mod.set_secret("KEY", _make_fake_blob())
    assert storage_mod.VAULT_FILE.exists()


@pytest.mark.skipif(IS_WINDOWS, reason="Unix file permissions not supported on Windows")
def test_vault_file_has_restricted_permissions():
    storage_mod.set_secret("KEY", _make_fake_blob())
    mode = oct(os.stat(storage_mod.VAULT_FILE).st_mode)
    assert mode.endswith("600")


# ── delete_secret ──────────────────────────────────────────────────────────────

def test_delete_existing_key():
    storage_mod.set_secret("TO_DELETE", _make_fake_blob())
    result = storage_mod.delete_secret("TO_DELETE")
    assert result is True
    assert storage_mod.get_secret("TO_DELETE") is None


def test_delete_missing_key_returns_false():
    result = storage_mod.delete_secret("NEVER_SET")
    assert result is False


def test_delete_only_removes_target_key():
    storage_mod.set_secret("KEY_A", _make_fake_blob("a"))
    storage_mod.set_secret("KEY_B", _make_fake_blob("b"))
    storage_mod.delete_secret("KEY_A")
    assert storage_mod.get_secret("KEY_B") is not None


# ── list_keys ──────────────────────────────────────────────────────────────────

def test_list_keys_returns_sorted():
    storage_mod.set_secret("ZEBRA", _make_fake_blob())
    storage_mod.set_secret("APPLE", _make_fake_blob())
    storage_mod.set_secret("MANGO", _make_fake_blob())
    keys = storage_mod.list_keys()
    assert keys == sorted(keys)


def test_list_keys_empty_vault():
    storage_mod.VAULT_FILE.write_text("{}")
    assert storage_mod.list_keys() == []


def test_list_keys_after_delete():
    storage_mod.set_secret("KEY_A", _make_fake_blob())
    storage_mod.set_secret("KEY_B", _make_fake_blob())
    storage_mod.delete_secret("KEY_A")
    keys = storage_mod.list_keys()
    assert "KEY_A" not in keys
    assert "KEY_B" in keys


# ── search_keys (Trie integration) ────────────────────────────────────────────

def test_search_keys_returns_prefix_matches():
    storage_mod.set_secret("AWS_KEY", _make_fake_blob())
    storage_mod.set_secret("AWS_SECRET", _make_fake_blob())
    storage_mod.set_secret("AWS_TOKEN", _make_fake_blob())
    storage_mod.set_secret("DB_HOST", _make_fake_blob())
    results = storage_mod.search_keys("AWS_")
    assert set(results) == {"AWS_KEY", "AWS_SECRET", "AWS_TOKEN"}


def test_search_keys_no_matches():
    storage_mod.set_secret("DB_HOST", _make_fake_blob())
    results = storage_mod.search_keys("STRIPE_")
    assert results == []


def test_search_keys_empty_prefix_returns_all():
    storage_mod.set_secret("KEY_A", _make_fake_blob())
    storage_mod.set_secret("KEY_B", _make_fake_blob())
    results = storage_mod.search_keys("")
    assert "KEY_A" in results
    assert "KEY_B" in results


# ── check_vault_permissions ────────────────────────────────────────────────────

def test_permissions_ok_returns_none():
    storage_mod.set_secret("KEY", _make_fake_blob())
    assert storage_mod.check_vault_permissions() is None


@pytest.mark.skipif(IS_WINDOWS, reason="Unix file permissions not supported on Windows")
def test_unsafe_permissions_returns_warning():
    storage_mod.set_secret("KEY", _make_fake_blob())
    os.chmod(storage_mod.VAULT_FILE, 0o644)
    warning = storage_mod.check_vault_permissions()
    assert warning is not None
    assert "WARNING" in warning
    assert "chmod 600" in warning


def test_no_vault_file_returns_none():
    assert storage_mod.check_vault_permissions() is None