from app.main import app
from app.policy import evaluate_access
from app.ledger import calculate_hash
from fastapi.testclient import TestClient

client = TestClient(app)


def test_home():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200


def test_trusted_device_policy():
    result = evaluate_access(
        authenticated=True,
        device_posture="managed",
        ip_address="127.0.0.1",
        role="user"
    )
    assert result["decision"] == "ALLOW"


def test_unknown_device_policy():
    result = evaluate_access(
        authenticated=True,
        device_posture="unknown",
        ip_address="127.0.0.1",
        role="user"
    )
    assert result["decision"] == "BLOCK"


def test_unauthenticated_policy():
    result = evaluate_access(
        authenticated=False,
        device_posture="managed",
        ip_address="127.0.0.1",
        role="user"
    )
    assert result["decision"] == "BLOCK"


def test_ledger_hash_changes_when_data_changes():
    block = {
        "index": 0,
        "did": "did:zaalima:test",
        "public_key": "abc",
        "previous_hash": "0" * 64
    }

    original = calculate_hash(block)
    modified = {**block, "did": "did:zaalima:changed"}

    assert original != calculate_hash(modified)