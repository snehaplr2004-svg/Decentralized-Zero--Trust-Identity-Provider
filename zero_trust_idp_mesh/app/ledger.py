
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from pathlib import Path
from contextlib import closing


# Database location: project root
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "zero_trust.db"


class IdentityLedger:

    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self._create_table()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    # Create ledger table
    def _create_table(self):
        with closing(self._get_connection()) as conn:
            with conn:
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

    # Add a new identity to the ledger
    def anchor(self, did, document):

        with closing(self._get_connection()) as conn:
            with conn:

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

    # Convert database row into a dictionary
    def _row_to_entry(self, row):

        return {
            "id": row[0],
            "did": row[1],
            "document": json.loads(row[2]),
            "timestamp": row[3],
            "previous_hash": row[4],
            "hash": row[5]
        }

    # Retrieve all ledger entries
    def list_entries(self):

        with closing(self._get_connection()) as conn:
            rows = conn.execute("""
                SELECT id, did, document, timestamp,
                       previous_hash, hash
                FROM ledger
                ORDER BY id ASC
            """).fetchall()

        return [
            self._row_to_entry(row)
            for row in rows
        ]

    # Retrieve ledger entries using pagination
    def list_entries_paginated(self, skip=0, limit=10):

        with closing(self._get_connection()) as conn:

            total = conn.execute("""
                SELECT COUNT(*) FROM ledger
            """).fetchone()[0]

            rows = conn.execute("""
                SELECT id, did, document, timestamp,
                       previous_hash, hash
                FROM ledger
                ORDER BY id ASC
                LIMIT ? OFFSET ?
            """, (limit, skip)).fetchall()

        entries = [
            self._row_to_entry(row)
            for row in rows
        ]

        return {
            "total_entries": total,
            "skip": skip,
            "limit": limit,
            "returned_entries": len(entries),
            "entries": entries
        }

    # Search ledger entries using an exact DID
    def search_by_did(self, did):

        with closing(self._get_connection()) as conn:
            rows = conn.execute("""
                SELECT id, did, document, timestamp,
                       previous_hash, hash
                FROM ledger
                WHERE did = ?
                ORDER BY id ASC
            """, (did,)).fetchall()

        return [
            self._row_to_entry(row)
            for row in rows
        ]

    # Retrieve one ledger entry using its ID
    def get_entry(self, entry_id):

        with closing(self._get_connection()) as conn:
            row = conn.execute("""
                SELECT id, did, document, timestamp,
                       previous_hash, hash
                FROM ledger
                WHERE id = ?
            """, (entry_id,)).fetchone()

        if row is None:
            return None

        return self._row_to_entry(row)

    # Verify the complete ledger hash chain
    def verify_chain(self):

        entries = self.list_entries()
        expected_previous_hash = "GENESIS"

        for index, entry in enumerate(entries, start=1):

            if entry["previous_hash"] != expected_previous_hash:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "checked_entries": index - 1,
                    "failed_entry": index,
                    "reason": "Previous hash mismatch",
                    "message": "Ledger integrity check failed"
                }

            entry_data = {
                "did": entry["did"],
                "document": entry["document"],
                "timestamp": entry["timestamp"],
                "previous_hash": entry["previous_hash"]
            }

            encoded = json.dumps(
                entry_data, sort_keys=True
            ).encode()

            calculated_hash = hashlib.sha256(
                encoded
            ).hexdigest()

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


# Create ledger instance
ledger = IdentityLedger()
