
import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.fixture
def client(monkeypatch):

    # Keep existing API tests independent of Gmail.
    monkeypatch.setattr(
        main.settings,
        "email_mfa_enabled",
        False
    )

    monkeypatch.setattr(
        main.settings,
        "expose_development_otp",
        True
    )

    return TestClient(main.app)


TEST_SUBJECT = "automated_api_test"
TEST_DID = "did:key:automated_test_123"


def mock_identity():
    return {
        "did": TEST_DID,
        "document": {}
    }


def test_health_endpoint(client):

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_identity_registration(client, monkeypatch):

    identity = {
        "did": TEST_DID,
        "document": {"id": TEST_DID}
    }

    monkeypatch.setattr(
        main,
        "create_did_identity",
        lambda subject: identity
    )

    monkeypatch.setattr(
        main.identity_registry,
        "register_identity_with_ledger",
        lambda subject, data: {
            "id": 999,
            "did": TEST_DID
        }
    )

    response = client.post(
        "/identities",
        json={"subject": TEST_SUBJECT}
    )

    assert response.status_code == 200
    assert response.json()["did"] == TEST_DID


def test_duplicate_identity_rejected(client, monkeypatch):

    monkeypatch.setattr(
        main,
        "create_did_identity",
        lambda subject: mock_identity()
    )

    monkeypatch.setattr(
        main.identity_registry,
        "register_identity_with_ledger",
        lambda subject, data: None
    )

    response = client.post(
        "/identities",
        json={"subject": TEST_SUBJECT}
    )

    assert response.status_code == 409


def test_unknown_identity_rejected(client, monkeypatch):

    monkeypatch.setattr(
        main.identity_registry,
        "get_identity",
        lambda subject: None
    )

    response = client.post(
        "/token",
        json={
            "subject": TEST_SUBJECT,
            "did": TEST_DID
        }
    )

    assert response.status_code == 401


def test_high_risk_ip_denied(client, monkeypatch):

    monkeypatch.setattr(
        main.identity_registry,
        "get_identity",
        lambda subject: mock_identity()
    )

    response = client.post(
        "/token",
        json={
            "subject": TEST_SUBJECT,
            "did": TEST_DID,
            "ip_address": "203.0.113.25",
            "device_posture": "compliant"
        }
    )

    assert response.status_code == 403
    assert response.json()["detail"]["risk"]["decision"] == "deny"


def test_normal_login_and_protected_access(client, monkeypatch):

    monkeypatch.setattr(
        main.identity_registry,
        "get_identity",
        lambda subject: mock_identity()
    )

    response = client.post(
        "/token",
        json={
            "subject": TEST_SUBJECT,
            "did": TEST_DID,
            "ip_address": "127.0.0.1",
            "device_posture": "compliant"
        }
    )

    assert response.status_code == 200
    assert response.json()["mfa_required"] is False

    token = response.json()["access_token"]

    protected = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert protected.status_code == 200
    assert protected.json()["subject"] == TEST_SUBJECT


def test_mfa_challenge_and_verification(client, monkeypatch):

    monkeypatch.setattr(
        main.identity_registry,
        "get_identity",
        lambda subject: mock_identity()
    )

    response = client.post(
        "/token",
        json={
            "subject": TEST_SUBJECT,
            "did": TEST_DID,
            "ip_address": "127.0.0.1",
            "device_posture": "untrusted"
        }
    )

    assert response.status_code == 200

    challenge = response.json()

    assert challenge["mfa_required"] is True
    assert "development_otp" in challenge

    verification = client.post(
        "/mfa/verify",
        json={
            "challenge_id": challenge["challenge_id"],
            "otp": challenge["development_otp"]
        }
    )

    assert verification.status_code == 200
    assert verification.json()["mfa_verified"] is True

    token = verification.json()["access_token"]

    protected = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert protected.status_code == 200
    assert protected.json()["subject"] == TEST_SUBJECT


def test_protected_endpoint_rejects_missing_token(client):

    response = client.get("/protected")

    assert response.status_code == 401
