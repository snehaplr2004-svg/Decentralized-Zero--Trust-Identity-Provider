TRUSTED_DEVICES = {"managed", "trusted"}


def evaluate_access(
    authenticated: bool,
    device_posture: str,
    ip_address: str,
    role: str
):
    checks = {
        "authenticated": authenticated,
        "trusted_device": device_posture in TRUSTED_DEVICES,
        "ip_present": bool(ip_address.strip()),
        "valid_role": role in {"user", "admin"}
    }

    allowed = all(checks.values())

    return {
        "decision": "ALLOW" if allowed else "BLOCK",
        "checks": checks,
        "reason": (
            "All demo policy checks passed"
            if allowed
            else "One or more policy checks failed"
        )
    }