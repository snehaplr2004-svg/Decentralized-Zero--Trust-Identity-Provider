from app.mfa import MFAService


def test_mfa_challenge_survives_service_restart(tmp_path):

    # Create a temporary database for this test.
    db_path = tmp_path / "test_mfa.db"

    # First service instance creates the challenge.
    first_service = MFAService(db_path=db_path)

    challenge = first_service.create_challenge(
        "persistence_test_user",
        "did:key:test123"
    )

    challenge_id = challenge["challenge_id"]
    otp = challenge["otp"]

    # Simulate an application restart by creating
    # a completely new MFAService instance.
    second_service = MFAService(db_path=db_path)

    # Verify using the second instance.
    result = second_service.verify_challenge(
        challenge_id,
        otp
    )

    assert result["valid"] is True
    assert result["subject"] == "persistence_test_user"
    assert result["did"] == "did:key:test123"

    # Confirm that the OTP cannot be reused.
    reuse_result = second_service.verify_challenge(
        challenge_id,
        otp
    )

    assert reuse_result["valid"] is False