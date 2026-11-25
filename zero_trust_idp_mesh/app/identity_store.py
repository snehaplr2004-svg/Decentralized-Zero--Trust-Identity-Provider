
import json
import sqlite3
import hashlib

from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "zero_trust.db"


class IdentityRegistry:

    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self.create_table()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def create_table(self):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS identities (
                        subject TEXT PRIMARY KEY,
                        did TEXT NOT NULL UNIQUE,
                        document TEXT NOT NULL
                    )
                """)

    def add_identity(self, subject, identity):
        try:
            with closing(self.get_connection()) as conn:
                with conn:
                    conn.execute("""
                        INSERT INTO identities
                        (subject, did, document)
                        VALUES (?, ?, ?)
                    """, (
                        subject,
                        identity["did"],
                        json.dumps(identity["document"], sort_keys=True)
                    ))
            return True

        except sqlite3.IntegrityError:
            return False

    def get_identity(self, subject):
        with closing(self.get_connection()) as conn:
            row = conn.execute("""
                SELECT subject, did, document
                FROM identities
                WHERE subject = ?
            """, (subject,)).fetchone()

        if row is None:
            return None

        return {
            "subject": row[0],
            "did": row[1],
            "document": json.loads(row[2])
        }

    def register_identity_with_ledger(self, subject, identity):
        """
        Save an identity and its ledger entry in one transaction.
        Both operations succeed or both are rolled back.
        """

        document = identity["document"]

        try:
            with closing(self.get_connection()) as conn:
                conn.execute("BEGIN IMMEDIATE")

                # Insert identity
                conn.execute("""
                    INSERT INTO identities
                    (subject, did, document)
                    VALUES (?, ?, ?)
                """, (
                    subject,
                    identity["did"],
                    json.dumps(document, sort_keys=True)
                ))

                # Get previous ledger hash
                previous = conn.execute("""
                    SELECT hash
                    FROM ledger
                    ORDER BY id DESC
                    LIMIT 1
                """).fetchone()

                previous_hash = (
                    previous[0] if previous else "GENESIS"
                )

                # Prepare ledger entry
                entry = {
                    "did": identity["did"],
                    "document": document,
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "previous_hash": previous_hash
                }

                # Calculate SHA-256 hash
                encoded = json.dumps(
                    entry,
                    sort_keys=True
                ).encode()

                entry["hash"] = hashlib.sha256(
                    encoded
                ).hexdigest()

                # Insert ledger entry
                conn.execute("""
                    INSERT INTO ledger (
                        did,
                        document,
                        timestamp,
                        previous_hash,
                        hash
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    identity["did"],
                    json.dumps(document, sort_keys=True),
                    entry["timestamp"],
                    previous_hash,
                    entry["hash"]
                ))

                # Commit both inserts together
                conn.commit()

                return entry

        except sqlite3.IntegrityError:
            return None


identity_registry = IdentityRegistry()
