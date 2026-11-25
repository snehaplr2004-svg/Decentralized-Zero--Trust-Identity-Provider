
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

    # Verify the complete ledger hash chain
    def verify_chain(self):

        entries = self.list_entries()

        expected_previous_hash = "GENESIS"

        for index, entry in enumerate(entries, start=1):

            # Verify previous hash connection
            if entry["previous_hash"] != expected_previous_hash:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "checked_entries": index - 1,
                    "failed_entry": index,
                    "reason": "Previous hash mismatch",
                    "message": "Ledger integrity check failed"
                }

            # Recreate original entry data
            entry_data = {
                "did": entry["did"],
                "document": entry["document"],
                "timestamp": entry["timestamp"],
                "previous_hash": entry["previous_hash"]
            }

            # Recalculate SHA-256 hash
            encoded = json.dumps(
                entry_data,
                sort_keys=True
            ).encode()

            calculated_hash = hashlib.sha256(
                encoded
            ).hexdigest()

            # Compare calculated hash with stored hash
            if calculated_hash != entry["hash"]:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "checked_entries": index - 1,
                    "failed_entry": index,
                    "reason": "Hash mismatch",
                    "message": "Ledger integrity check failed"
                }

            expected_previous_hash = entry["hash"]

        return {
            "valid": True,
            "total_entries": len(entries),
            "checked_entries": len(entries),
            "failed_entry": None,
            "reason": None,
            "message": "Ledger integrity verified successfully"
        }


ledger = IdentityLedger()
