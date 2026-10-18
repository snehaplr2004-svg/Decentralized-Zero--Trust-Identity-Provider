"""
Cryptographic primitives:
  - Ed25519 keypair generation
  - JWT minting (EdDSA) with jti for revocation
  - JWT verification
  - Server public key exposure (for JWKS)
"""
from datetime import datetime, timedelta, timezone
from typing import Any
import uuid
import base64

from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app.config import settings


def generate_ed25519_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) as PEM strings."""
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


def create_access_token(
    subject: str,
    did: str,
    extra: dict[str, Any] | None = None,
    ttl_seconds: int | None = None,
) -> str:
    """
    Mint a signed EdDSA JWT.
    A unique `jti` is always included so the token can be revoked later.
    """
    now = datetime.now(timezone.utc)
    ttl = ttl_seconds or settings.JWT_EXPIRE_SECONDS

    payload = {
        "iss": settings.ISSUER,
        "sub": subject,
        "did": did,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "aud": settings.ISSUER,
        **(extra or {}),
    }
    return jwt.encode(payload, _SERVER_PRIVATE_PEM, algorithm=settings.JWT_ALG)


def decode_token(token: str) -> dict:
    """Verify a JWT and return its claims, or raise ValueError."""
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


def server_public_pem() -> str:
    """Expose the server's public key (used by /.well-known/jwks.json)."""
    return _SERVER_PUBLIC_PEM


# Server signing keypair — loaded once at import.
# In production: pull from KMS / HSM / sealed secret.
_SERVER_PRIVATE_PEM, _SERVER_PUBLIC_PEM = generate_ed25519_keypair()