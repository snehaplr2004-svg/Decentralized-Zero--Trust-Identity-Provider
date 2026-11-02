import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

APP_NAME = os.getenv(
    "APP_NAME",
    "Zaalima Zero Trust Identity Provider"
)

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))

DATABASE_PATH = ROOT / os.getenv("DATABASE_PATH", "data/idp.db")
LEDGER_PATH = ROOT / os.getenv("LEDGER_PATH", "data/did_ledger.json")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

PRIVATE_KEY_ENCRYPTION_KEY = os.getenv("PRIVATE_KEY_ENCRYPTION_KEY", "")
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = os.getenv(
    "WEBAUTHN_RP_NAME", "Zaalima Identity Provider"
)
WEBAUTHN_ORIGIN = os.getenv(
    "WEBAUTHN_ORIGIN", "http://localhost:8000"
)

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)

if len(JWT_SECRET) < 32:
    raise RuntimeError(
        "Set JWT_SECRET to a random secret of at least 32 characters in .env"
    )