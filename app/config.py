"""
Central configuration for the Zero-Trust IdP.

Values are read from environment variables (or a .env file) via
pydantic-settings. Every other module imports `settings` from here.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Application
    APP_NAME: str = "Decentralized Zero-Trust IdP"
    ISSUER: str = "https://idp.mesh.local"
    BASE_URL: str = "http://localhost:8000"

    # Cryptography
    JWT_ALG: str = "EdDSA"                # ed25519 via EdDSA
    JWT_EXPIRE_SECONDS: int = 900
    DID_METHOD: str = "did:mesh"

    # Redis (Week 3 — revocation)
    REDIS_URL: str = "redis://localhost:6379/0"
    BLOOM_CAPACITY: int = 1_000_000
    BLOOM_ERROR_RATE: float = 0.001

    # WebAuthn (Week 2)
    RP_ID: str = "localhost"
    RP_NAME: str = "Mesh IdP"
    ORIGIN: str = "http://localhost:8000"


settings = Settings()