
import base64
import time
import uuid
import jwt

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.hazmat.primitives import serialization

# Demonstration key. Production must load a persistent,
# securely managed signing key.
SIGNING_KEY = Ed25519PrivateKey.generate()
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
