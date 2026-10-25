
from datetime import datetime, timezone


def evaluate_risk(
    ip_address: str,
    device_posture: str
):
    score = 0
    reasons = []

    blocked_prefixes = (
        "203.0.113.",
        "198.51.100."
    )

    if ip_address.startswith(blocked_prefixes):
        score += 80
        reasons.append("blocked_ip")

    if device_posture.lower() not in {
        "compliant", "managed", "healthy"
    }:
        score += 50
        reasons.append("untrusted_device")

    hour = datetime.now(timezone.utc).hour

    if hour < 6 or hour >= 22:
        score += 15
        reasons.append("unusual_access_time")

    if score >= 50:
        decision = "deny"
    elif score >= 25:
        decision = "step_up"
    else:
        decision = "allow"

    return {
        "score": score,
        "decision": decision,
        "reasons": reasons
    }
