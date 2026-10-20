JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_EXPIRE_MINUTES = int(
    os.getenv("JWT_EXPIRE_MINUTES", "30")
)

DATABASE_PATH = ROOT / os.getenv(
    "DATABASE_PATH", "data/idp.db"
)
LEDGER_PATH = ROOT / os.getenv(
    "LEDGER_PATH", "data/did_ledger.json"
)

REDIS_URL = os.getenv(
    "REDIS_URL", "redis://localhost:6379/0"
)

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)

if len(JWT_SECRET) < 32:
    raise RuntimeError(
        "Set JWT_SECRET to a random secret of at least 32 characters in .env"
    )