
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_logout_revokes_access_token():
    # Step 1: Create a new identity
    identity_response = client.post(
        "/identities",
        json={"subject": "logout_test_user"}
    )

    assert identity_response.status_code == 200

    did = identity_response.json()["did"]

    # Step 2: Generate an access token
    token_response = client.post(
        "/token",
        json={
            "subject": "logout_test_user",
            "did": did,
            "ip_address": "127.0.0.1",
            "device_posture": "compliant"
        }
    )

    assert token_response.status_code == 200

    token = token_response.json()["access_token"]

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Step 3: Verify access before logout
    protected_response = client.get(
        "/protected",
        headers=headers
    )

    assert protected_response.status_code == 200

    # Step 4: Logout and revoke the token
    logout_response = client.post(
        "/logout",
        headers=headers
    )

    assert logout_response.status_code == 200
    assert logout_response.json()["token_revoked"] is True

    # Step 5: Verify access is rejected after logout
    revoked_response = client.get(
        "/protected",
        headers=headers
    )

    assert revoked_response.status_code == 401
    assert revoked_response.json()["detail"] == "Token has been revoked"
