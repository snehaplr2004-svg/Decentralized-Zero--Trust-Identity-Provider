
import re
import uuid

from fastapi.testclient import TestClient

from app import main


client = TestClient(main.app)


def test_production_mfa_does_not_expose_otp(monkeypatch):

    # Simulate production configuration.
    monkeypatch.setattr(
        main.settings,
        "environment",
        "production"
    )

    monkeypatch.setattr(
        main.settings,
        "expose_development_otp",
        False
    )

    monkeypatch.setattr(
        main.settings,
        "email_mfa_enabled",
        True
    )

    # Provide test-only SMTP configuration.
    # No real Gmail connection will be made.
    monkeypatch.setattr(
        main.settings,
        "smtp_host",
        "smtp.gmail.com"
    )

    monkeypatch.setattr(
        main.settings,
        "smtp_port",
        587
    )

    monkeypatch.setattr(
        main.settings,
        "smtp_username",
        "test@example.com"
    )

    monkeypatch.setattr(
        main.settings,
        "smtp_password",
        "test-password"
    )

    monkeypatch.setattr(
        main.settings,
        "email_from",
        "test@example.com"
    )

    # Capture mocked email delivery.
    sent_emails = []

    def mock_send_email(recipient, otp):
        sent_emails.append({
            "recipient": recipient,
            "otp": otp
        })
        return True

    monkeypatch.setattr(
        main,
        "send_otp_email",
        mock_send_email
    )

    subject = f"production_mfa_{uuid.uuid4().hex[:12]}"
    email = "mfa-test@example.com"

    # Register a unique identity with an email address.
    identity_response = client.post(
        "/identities",
        json={
            "subject": subject,
            "email": email
        }
    )

    assert identity_response.status_code == 200

    did = identity_response.json()["did"]

    # An untrusted device triggers MFA.
    token_response = client.post(
        "/token",
        json={
            "subject": subject,
            "did": did,
            "ip_address": "127.0.0.1",
            "device_posture": "untrusted"
        }
    )

    assert token_response.status_code == 200

    response_data = token_response.json()

    assert response_data["mfa_required"] is True
    assert "challenge_id" in response_data

    # Production API must never expose the OTP.
    assert "development_otp" not in response_data

    # Confirm that the OTP was sent to the registered email
    # through our mocked email function.
    assert len(sent_emails) == 1
    assert sent_emails[0]["recipient"] == email
    assert re.fullmatch(
        r"\d{6}",
        sent_emails[0]["otp"]
    )
