from app.api.ztna import evaluate_risk
from app.models.schemas import RiskSignals


def test_high_risk_denied():
    s = RiskSignals(
        ip_reputation=0.2,
        device_posture=0.3,
        hour_of_day=3,
        geo_velocity_kmh=5000,
    )
    score, reasons = evaluate_risk(s)
    assert score < 0.45
    assert any("IP" in r for r in reasons)


def test_low_risk_allowed():
    s = RiskSignals(
        ip_reputation=0.9,
        device_posture=0.95,
        hour_of_day=14,
        geo_velocity_kmh=50,
    )
    score, _ = evaluate_risk(s)
    assert score >= 0.75


def test_medium_risk_step_up():
    s = RiskSignals