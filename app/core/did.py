"""
Decentralized Identifier (DID) helpers.

Format: did:mesh:<multibase-ed25519-pubkey>

We use a W3C-compliant DID Document with an Ed25519VerificationKey2020
verification method.
"""
from cryptography.hazmat.primitives import serialization
import base58

from app.config import settings


def _pubkey_to_multibase(pub_pem: str) -> str:
    """
    Encode an Ed25519 public key as a multibase (base58btc) string
    with the ed25519-pub multicodec prefix 0xed01.
    """
    pub = serialization.load_pem_public_key(pub_pem.encode())
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "z" + base58.b58encode(b"\xed\x01" + raw).decode()


def create_did(public_pem: str) -> str:
    """Derive a deterministic DID from a public key."""
    return f"{settings.DID_METHOD}:{_pubkey_to_multibase(public_pem)}"


def build_did_document(did: str, public_pem: str) -> dict:
    """Build a minimal W3C DID Document for this keypair."""
    multibase = _pubkey_to_multibase(public_pem)
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [
            {
                "id": f"{did}#idp",
                "type": "ZeroTrustIdP",
                "serviceEndpoint": settings.BASE_URL,
            }
        ],
    }