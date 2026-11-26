
from app.mfa import MFAService


def test_create_mfa_challenge():
    service = MFAService()

    challenge = service.create_challenge(
        "test_user",
        "did:key:test123"
    )

    assert "challenge_id" in challenge
    assert len(challenge["otp"]) == 6
    assert challenge["otp"].isdigit()


def test_valid_otp_verification():
    service = MFAService()

    challenge = service.create_challenge(
        "test_user",
        "did:key:test123"
    )

    result = service.verify_challenge(
        challenge["challenge_id"],
        challenge["otp"]
    )

    assert result["valid"] is True
    assert result["subject"] == "test_user"
    assert result["did"] == "did:key:test123"


def test_otp_cannot_be_reused():
    service = MFAService()

    challenge = service.create_challenge(
        "test_user",
        "did:key:test123"
    )

    first_result = service.verify_challenge(
        challenge["challenge_id"],
        challenge["otp"]
    )

    second_result = service.verify_challenge(
        challenge["challenge_id"],
        challenge["otp"]
    )

    assert first_result["valid"] is True
    assert second_result["valid"] is False


def test_incorrect_otp_is_rejected():
    service = MFAService()

    challenge = service.create_challenge(
        "test_user",
        "did:key:test123"
    )

    result = service.verify_challenge(
        challenge["challenge_id"],
        "000000"
        if challenge["otp"] != "000000"
        else "000001"
    )

    assert result["valid"] is False
    assert result["reason"] == "Incorrect OTP"
    assert result["remaining_attempts"] == 4
