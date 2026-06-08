import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
NONCE_SIZE = 12  
PBKDF2_ITERATIONS = 600_000
KEY_SIZE = 32

def derive_key(password: str, salt: bytes) -> bytes:

    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,

    )

def encrypt(plaintext: str, password: str) -> dict:

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }

def decrypt(blob: dict, password: str) -> str:

    salt = bytes.fromhex(blob["salt"])
    nonce = bytes.fromhex(blob["nonce"])
    ciphertext = bytes.fromhex(blob["ciphertext"])
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext_bytes.decode("utf-8")
