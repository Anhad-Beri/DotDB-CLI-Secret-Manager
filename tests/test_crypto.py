import pytest
from cryptography.exceptions import InvalidTag
from vault.crypto import encrypt, decrypt


def test_encrypt_returns_required_fields():
    blob = encrypt("my_secret", "password123")
    assert "salt" in blob
    assert "nonce" in blob
    assert "ciphertext" in blob


def test_decrypt_roundtrip():
    value = "super_secret_value"
    password = "master_password"
    blob = encrypt(value, password)
    assert decrypt(blob, password) == value


def test_wrong_password_raises():
    blob = encrypt("secret", "correct_password")
    with pytest.raises(InvalidTag):
        decrypt(blob, "wrong_password")


def test_each_encryption_is_unique():
    blob1 = encrypt("same_value", "same_password")
    blob2 = encrypt("same_value", "same_password")
    assert blob1["ciphertext"] != blob2["ciphertext"]
    assert blob1["salt"] != blob2["salt"]


def test_tampered_ciphertext_raises():
    blob = encrypt("secret", "password")
    tampered = dict(blob)
    tampered["ciphertext"] = "deadbeef" * 10
    with pytest.raises(Exception):
        decrypt(tampered, "password")