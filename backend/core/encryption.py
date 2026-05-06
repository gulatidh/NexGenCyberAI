"""
NexGenCyberAI - Field-level encryption for connector credentials stored in DB.
Uses Fernet (AES-128-CBC + HMAC-SHA256).
"""
from cryptography.fernet import Fernet
from core.config import get_settings
import base64
import hashlib

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        raw = get_settings().ENCRYPTION_KEY or "dev-insecure-key-replace-in-prod"
        key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
        _fernet = Fernet(key)
    return _fernet


def encrypt(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()
