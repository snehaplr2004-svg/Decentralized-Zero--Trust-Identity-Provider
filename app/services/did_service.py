"""
DID service — thin wrapper around core.did + ledger.

Keeps the API layer free of crypto details.
"""
from app.core.did import create_did, build_did_document
from app.core.security import generate_ed25519_keypair
from app.ledger.blockchain import ledger


def register_did() -> dict:
    """Generate a fresh keypair, build its DID doc, anchor it, return all."""
    priv_pem, pub_pem = generate_ed25519_keypair()
    did = create_did(pub_pem)
    doc = build_did_document(did, pub_pem)
    block = ledger.anchor(doc)
    return {
        "did": did,
        "did_document": doc,
        "private_key_pem": priv_pem,
        "anchored_in_block": block.index,
        "block_hash": block.hash,
    }


def resolve_did(did: str) -> dict | None:
    """Look up a DID Document on the ledger."""
    return ledger.get_did(did)