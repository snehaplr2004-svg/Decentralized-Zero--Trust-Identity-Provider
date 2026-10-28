import base64
import hashlib
import hmac
import json
import secrets
import jwt

from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from .config import (
    JWT_SECRET, JWT_EXPIRE_MINUTES, PRIVATE_KEY_ENCRYPTION_KEY
)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 310_000
    result = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations
    )
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(result).decode()
    )
