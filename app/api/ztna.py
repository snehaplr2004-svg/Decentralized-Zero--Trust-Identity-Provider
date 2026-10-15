"""
Zero-Trust Network Access (ZTNA) policy engine.

Risk score = weighted sum of signals clamped to [0, 1]:
  score >= 0.75  → allow, full TTL
  0.45–0.75      → allow, step-up (short TTL)
  score < 0.45   → deny
"""
import logging

from fastapi import APIRouter, Header, HTTPException, status

from app.core.security import decode_token, create_access_token
from app.models.schemas import (
    RiskSignals, ZTNADecision, RevokeResponse, RiskTier,
)
from app.services.revocation import revoke, is_revoked, stats

logger = logging.getLogger(__name__)
router = APIRouter()


# ----- Weights -----
W_IP = 0.35
W_DEVICE = 0.30
W_HOUR = 0.15
W_VELOCITY = 0.20

ALLOW_THRESHOLD = 0.75
STEP_UP_THRESHOLD = 0.45

STEP_UP_TTL = 120
FULL_TTL = 900


def _hour_score(hour: int) -> float:
    if 8 <= hour <= 20:
        return 1.0
    if 6 <= hour < 8 or 20 < hour <= 22:
        return 0.6
    return 0.2


def _velocity_score(kmh: float) -> float:
    if kmh <= 100:
        return 1.0
    if kmh >= 1000:
        return 0.0
    return 1.0 - (kmh - 100) / 900.0


def evaluate_risk(s: RiskSignals) -> tuple[float, list[str]]:
    """Return (score, reasons)."""
    hour_component = _hour_score(s.hour_of_day)
    velocity_component = _velocity_score(s.geo_velocity_kmh)

    score = (
        W_IP * s.ip_reputation
        + W_DEVICE * s.device_posture
        + W_HOUR * hour_component
        + W_VELOCITY * velocity_component
    )
    score = max(0.0, min(1.0, score))

    reasons: list[str] = []
    if s.ip_reputation < 0.4:
        reasons.append(f"low IP reputation ({s.ip_reputation:.2f})")
    if s.device_posture < 0.5:
        reasons.append(f"poor device posture ({s.device_posture:.2f})")
    if s.geo_velocity_kmh > 1000:
        reasons.append(f"impossible travel ({s.geo_velocity_kmh:.0f} km/h)")
    if s.hour_of_day < 6 or s.hour_of_day > 22:
        reasons.append(f"off-hours access (hour={s.hour_of_day})")

    return score, reasons


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Missing or malformed Authorization header",
        )
    return authorization.split(" ", 1)[1]


@router.post("/evaluate", response_model=ZTNADecision)
async def evaluate(
    signals: RiskSignals,
    authorization: str | None = Header(None),
):
    token = _bearer_token(authorization)

    try:
        claims = decode_token(token)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))

    jti = claims.get("jti", "")
    if jti and is_revoked(jti):
        logger.warning("Denied revoked token jti=%s", jti)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has been revoked")

    score, reasons = evaluate_risk(signals)
    logger.info(
        "ZTNA sub=%s did=%s score=%.3f reasons=%s",
        claims.get("sub"), claims.get("did"), score, reasons,
    )

    if score < STEP_UP_THRESHOLD:
        return ZTNADecision(
            allow=False,
            risk_score=round(score, 3),
            reasons=reasons or ["risk below policy floor"],
        )

    if score < ALLOW_THRESHOLD:
        step_up = create_access_token(
            subject=claims["sub"],
            did=claims["did"],
            extra={"scope": "step_up", "parent_jti": jti},
            ttl_seconds=STEP_UP_TTL,
        )
        return ZTNADecision(
            allow=True,
            risk_score=round(score, 3),
            reasons=reasons or ["step-up required"],
            step_up_token=step_up,
            ttl_seconds=STEP_UP_TTL,
        )

    refreshed = create_access_token(
        subject=claims["sub"],
        did=claims["did"],
        ttl_seconds=FULL_TTL,
    )
    return ZTNADecision(
        allow=True,
        risk_score=round(score, 3),
        reasons=reasons or ["all signals nominal"],
        step_up_token=refreshed,
        ttl_seconds=FULL_TTL,
    )


@router.post("/revoke/{jti}", response_model=RevokeResponse)
async def revoke_token(jti: str):
    count = revoke(jti)
    return RevokeResponse(jti=jti, revoked=True, total_revoked=count)


@router.get("/revocation/stats")
async def revocation_stats():
    return stats()


@router.get("/policy", response_model=list[RiskTier])
async def policy_tiers():
    return [
        RiskTier(tier="low", min_score=ALLOW_THRESHOLD, max_score=1.0),
        RiskTier(tier="medium", min_score=STEP_UP_THRESHOLD, max_score=ALLOW_THRESHOLD),
        RiskTier(tier="high", min_score=0.0, max_score=STEP_UP_THRESHOLD),
    ]