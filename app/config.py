from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "Decentralized Zero-Trust IdP"
    ISSUER: str = "https://idp.mesh.local"
    BASE_URL: str = "http://localhost:8000"

    # Crypto
    JWT_ALG: str = "EdDSA"          # ed25519 via EdDSA
    JWT_EXPIRE_SECONDS: int = 900
    DID_METHOD: str = "did:mesh"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    BLOOM_CAPACITY: int = 1_000_000
    BLOOM_ERROR_RATE: float = 0.001

    # WebAuthn
    RP_ID: str = "localhost"
    RP_NAME: str = "Mesh IdP"
    ORIGIN: str = "http://localhost:8000"

    class Config:
        env_file = ".env"

settings = Settings()