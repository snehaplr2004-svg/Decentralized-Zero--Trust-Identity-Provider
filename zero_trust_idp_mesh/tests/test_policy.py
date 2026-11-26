
from app.policy import evaluate_risk


def test_allow_compliant_device():
    result = evaluate_risk(
        "127.0.0.1",
        "compliant"
    )

    assert result["decision"] == "allow"
    assert result["score"] < 25


def test_step_up_for_untrusted_device():
    result = evaluate_risk(
        "127.0.0.1",
        "untrusted"
    )

    assert result["decision"] == "step_up"
    assert result["score"] >= 25
    assert "untrusted_device" in result["reasons"]


def test_deny_blocked_ip():
    result = evaluate_risk(
        "203.0.113.25",
        "compliant"
    )

    assert result["decision"] == "deny"
    assert result["score"] >= 50
    assert "blocked_ip" in result["reasons"]


def test_untrusted_device_with_unusual_time():
    result = evaluate_risk(
        "127.0.0.1",
        "untrusted"
    )

    assert result["decision"] == "step_up"
    assert result["score"] >= 30
