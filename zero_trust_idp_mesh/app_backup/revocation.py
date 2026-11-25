
import sqlite3
import time
from pathlib import Path
from threading import Lock


# Store the database in the main project folder.
DB_PATH = Path(__file__).resolve().parent.parent / "revocations.db"


class TokenRevocationList:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.lock = Lock()

        # Create the database and table if they do not exist.
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path, timeout=10) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    jti TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL
                )
            """)

    def revoke(self, jti: str, expires_at: int):
        """Save a revoked token ID and its expiry time."""
        with self.lock:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO revoked_tokens
                    (jti, expires_at)
                    VALUES (?, ?)
                    """,
                    (jti, expires_at)
                )

    def is_revoked(self, jti: str) -> bool:
        """Check whether a token ID is currently revoked."""
        now = int(time.time())

        with self.lock:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                # Remove revocation records for expired tokens.
                conn.execute(
                    "DELETE FROM revoked_tokens WHERE expires_at <= ?",
                    (now,)
                )

                result = conn.execute(
                    "SELECT 1 FROM revoked_tokens WHERE jti = ?",
                    (jti,)
                ).fetchone()

                return result is not None

    def remove(self, jti: str):
        """Remove a token ID from the revocation database."""
        with self.lock:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                conn.execute(
                    "DELETE FROM revoked_tokens WHERE jti = ?",
                    (jti,)
                )


revocation_list = TokenRevocationList()
