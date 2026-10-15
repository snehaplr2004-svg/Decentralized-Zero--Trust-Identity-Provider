from pydantic import BaseModel, Field
from typing import Literal


# ---------- WebAuthn (Week 2) ----------
class RegBegin(BaseModel):
    did: str
    username: str


class RegComplete(BaseModel):
    did: str
    credential: dict


class AuthBegin(BaseModel):
    did: str


class AuthComplete(BaseModel):
    did: str
    credential: dict


# ---------- ZTNA (Week 3) ----------
class RiskSignals(BaseModel):
    ip_reputation: float = Field(
        ..., ge=0.0, le=1.0,
        description="0.0 = known malicious, 1.0 = trusted ASN",
    )
    device_posture: float = Field(
        ..., ge=0.0, le=1.0,
        description="0.0 = unpatched/rooted, 1.0 = compliant MDM device",
    )
    hour_of_day: int = Field(
        ..., ge=0, le=23,
        description="Local hour for the user (business-hours boost)",
    )
    geo_velocity_kmh: float = Field(
        0.0, ge=0.0,
        description="Speed since last login; impossible travel if > 1000",
    )


class ZTNADecision(BaseModel):
    allow: bool
    risk_score: float
    reasons: list[str]
    step_up_token: str | None = None
    ttl_seconds: int | None = None


class RevokeResponse(BaseModel):
    jti: str
    revoked: bool
    total_revoked: int


class RiskTier(BaseModel):
    tier: Literal["low", "medium", "high"]
    min_score: float
    max_score: float