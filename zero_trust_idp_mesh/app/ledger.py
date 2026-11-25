
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from pathlib import Path


# Database location: project root
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "zero_trust.db"


class IdentityLedger:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self._create_table()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _create_table(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    did TEXT NOT NULL,
                    document TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    hash TEXT NOT NULL UNIQUE
                )
            """)

    def anchor(self, did, document):
        with self._get_connection() as conn:

            previous = conn.execute(
                "SELECT hash FROM ledger ORDER BY id DESC LIMIT 1"
            ).fetchone()

            previous_hash = previous[0] if previous else "GENESIS"

            entry = {
                "did": did,
                "document": document,
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "previous_hash": previous_hash
            }

            encoded = json.dumps(
                entry, sort_keys=True
            ).encode()

            entry["hash"] = hashlib.sha256(
                encoded
            ).hexdigest()

            conn.execute("""
                INSERT INTO ledger (
                    did, document, timestamp,
                    previous_hash, hash
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                did,
                json.dumps(document, sort_keys=True),
                entry["timestamp"],
                previous_hash,
                entry["hash"]
            ))

            return entry

    def list_entries(self):
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT did, document, timestamp,
                       previous_hash, hash
                FROM ledger
                ORDER BY id ASC
            """).fetchall()

        entries = []

        for row in rows:
            entries.append({
                "did": row[0],
                "document": json.loads(row[1]),
                "timestamp": row[2],
                "previous_hash": row[3],
                "hash": row[4]
            })

        return entries


ledger = IdentityLedger()
