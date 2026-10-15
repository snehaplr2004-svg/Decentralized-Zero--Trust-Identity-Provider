"""Pydantic schemas for all API endpoints."""
from typing import Literal
from pydantic import BaseModel, Field


# ---------- DIDs ----------
class DIDRegisterRequest(BaseModel):
    label: str | None = None


class DIDRegisterResponse(BaseModel):
    did: str
    did_document: dict
    private_key_pem: str
    anchored_in_block: int
    block_hash: str


# ---------- WebAuthn ----------
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


# ---------- ZTNA ----------
class RiskSignals(BaseModel):
    ip_reputation: float = Field(..., ge=0.0, le=1.0)
    device_posture: float = Field(..., ge=0.0, le=1.0)
    hour_of_day: int = Field(..., ge=0, le=23)
    geo_velocity_kmh: float = Field(0.0, ge=0.0)


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