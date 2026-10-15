from app.core.did import create_did, build_did_document
from app.core.security import generate_ed25519_keypair
from app.ledger.blockchain import SimulatedLedger


def test_did_creation_and_doc():
    _, pub = generate_ed25519_keypair()
    did = create_did(pub)
    assert did.startswith("did:mesh:")
    doc = build_did_document(did, pub)
    assert doc["id"] == did
    assert doc["verificationMethod"][0]["type"] == "Ed25519VerificationKey2020"


def test_ledger_anchor_and_verify():
    l = SimulatedLedger()
    _, pub = generate_ed25519_keypair()
    did = create_did(pub)
    doc = build_did_document(did, pub)
    block = l.anchor(doc)
    assert block.index == 1
    assert l.verify()
    assert l.get_did(did) == doc


def test_ledger_tamper_detected():
    l = SimulatedLedger()
    _, pub = generate_ed25519_keypair()
    doc = build_did_document(create_did(pub), pub)
    l.anchor(doc)
    l.chain[1].did_document["id"] = "did:mesh:tampered"
    assert not l.verify()