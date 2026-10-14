from datetime import datetime, timedelta, timezone
from typing import Any
from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
import base64

from app.config import settings


def generate_ed25519_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) as strings."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_access_token(subject: str, did: str, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": settings.ISSUER,
        "sub": subject,
        "did": did,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.JWT_EXPIRE_SECONDS)).timestamp()),
        "aud": settings.ISSUER,
        **(extra or {}),
    }
    # NOTE: for MVP we sign with a server-side key; in full impl, sign with DID key.
    return jwt.encode(payload, _SERVER_PRIVATE_PEM, algorithm=settings.JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            _SERVER_PUBLIC_PEM,
            algorithms=[settings.JWT_ALG],
            audience=settings.ISSUER,
            issuer=settings.ISSUER,
        )
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


# Server signing keypair (in prod: load from KMS / sealed secret)
_SERVER_PRIVATE_PEM, _SERVER_PUBLIC_PEM = generate_ed25519_keypair()