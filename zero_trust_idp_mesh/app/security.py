
import base64
import time
import uuid
from pathlib import Path

import jwt

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.hazmat.primitives import serialization


# Store the signing key in the project-level keys folder.
KEY_PATH = (
    Path(__file__).resolve().parent.parent
    / "keys"
    / "jwt_ed25519_private.pem"
)


def load_or_create_signing_key(key_path=KEY_PATH):
    """
    Load the existing Ed25519 private key.
    If no key exists, create and save one.
    """
    key_path = Path(key_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        with key_path.open("rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Stored signing key is not an Ed25519 key")

        return private_key

    private_key = Ed25519PrivateKey.generate()

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    key_path.write_bytes(pem_data)

    return private_key


# Load the same signing key whenever the application starts.
SIGNING_KEY = load_or_create_signing_key()
VERIFY_KEY = SIGNING_KEY.public_key()


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_did_identity(subject: str):
    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

    did = "did:key:z" + base64url(public_key)
    fingerprint = "z" + base64url(public_key)

    document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": f"{did}#{fingerprint}",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyBase64Url": base64url(public_key)
        }],
        "authentication": [f"{did}#{fingerprint}"]
    }

    return {
        "did": did,
        "document": document
    }


def issue_access_token(subject, did, scopes, risk):
    now = int(time.time())

    claims = {
        "iss": "http://localhost:8000",
        "aud": "idp-mesh-api",
        "sub": subject,
        "did": did,
        "scope": " ".join(scopes),
        "iat": now,
        "exp": now + 900,
        "jti": str(uuid.uuid4()),
        "risk": risk
    }

    return jwt.encode(
        claims,
        SIGNING_KEY,
        algorithm="EdDSA"
    )
