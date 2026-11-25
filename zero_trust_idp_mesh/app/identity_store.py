
import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "zero_trust.db"


class IdentityRegistry:

    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self.create_table()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def create_table(self):
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS identities (
                    subject TEXT PRIMARY KEY,
                    did TEXT NOT NULL UNIQUE,
                    document TEXT NOT NULL
                )
            """)

    def add_identity(self, subject, identity):
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO identities (subject, did, document)
                    VALUES (?, ?, ?)
                """, (
                    subject,
                    identity["did"],
                    json.dumps(identity["document"])
                ))
            return True

        except sqlite3.IntegrityError:
            return False

    def get_identity(self, subject):
        with self.get_connection() as conn:
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


identity_registry = IdentityRegistry()
