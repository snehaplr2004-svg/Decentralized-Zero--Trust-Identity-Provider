import hashlib
import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from app.config import settings


def _pubkey_to_multibase(pub_pem: str) -> str:
    pub = serialization.load_pem_public_key(pub_pem.encode())
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # multibase base58btc with ed25519 multicodec prefix 0xed01
    return "z" + base58.b58encode(b"\xed\x01" + raw).decode()


def create_did(public_pem: str) -> str:
    return f"{settings.DID_METHOD}:{_pubkey_to_multibase(public_pem)}"


def build_did_document(did: str, public_pem: str) -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": _pubkey_to_multibase(public_pem),
        }],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }