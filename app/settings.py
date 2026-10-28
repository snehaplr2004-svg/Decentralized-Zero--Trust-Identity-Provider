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
def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt)
        expected = base64.b64decode(expected)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False
def generate_identity():
    """Return (DID, base64url public key, raw private-key bytes)."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    public_b64 = base64.urlsafe_b64encode(
        public_bytes
    ).decode().rstrip("=")

    did_hash = hashlib.sha256(public_bytes).hexdigest()[:32]
    did = f"did:zaalima:{did_hash}"

    private_bytes = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption()
    )
    return did, public_b64, private_bytes
def _fernet() -> Fernet:
    if not PRIVATE_KEY_ENCRYPTION_KEY:
        raise RuntimeError(
            "Set PRIVATE_KEY_ENCRYPTION_KEY in .env before registering users"
        )
    try:
        return Fernet(PRIVATE_KEY_ENCRYPTION_KEY.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            "PRIVATE_KEY_ENCRYPTION_KEY must be a valid Fernet key"
        ) from exc
def encrypt_private_key(private_key_bytes: bytes) -> str:
    """Encrypt a raw Ed25519 private key before database storage."""
    return _fernet().encrypt(private_key_bytes).decode("utf-8")


def decrypt_private_key(encrypted_private_key: str) -> bytes:
    """Decrypt a stored private key. Keep the encryption key secret."""
    try:
        return _fernet().decrypt(encrypted_private_key.encode("utf-8"))
    except InvalidToken as exc:
        raise ValueError("Private key could not be decrypted") from exc
def sign_payload(private_key_bytes: bytes, payload: dict) -> str:
    """Sign canonical JSON with Ed25519; return base64url signature."""
    private = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    message = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    signature = private.sign(message)
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")
def verify_payload(public_key_b64: str, payload: dict, signature_b64: str) -> bool:
    """Verify an Ed25519 signature; return False for invalid input/signature."""
    try:
        public_bytes = base64.urlsafe_b64decode(
            public_key_b64 + "=" * (-len(public_key_b64) % 4)
        )
        signature = base64.urlsafe_b64decode(
            signature_b64 + "=" * (-len(signature_b64) % 4)
        )
        public = Ed25519PublicKey.from_public_bytes(public_bytes)
        message = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        public.verify(signature, message)
        return True
    except Exception:
        return False