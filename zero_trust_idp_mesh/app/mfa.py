
import hashlib
import secrets
import sqlite3
import time

from pathlib import Path
from threading import Lock
from contextlib import closing


# Use the existing identity database.
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "zero_trust.db"


class MFAService:

    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else DB_PATH

        self.lock = Lock()
        self.otp_expiry_seconds = 300
        self.max_attempts = 5

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.create_table()

    def get_connection(self):
        return sqlite3.connect(
            self.db_path,
            timeout=10
        )

    def create_table(self):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS mfa_challenges (
                        challenge_id TEXT PRIMARY KEY,
                        subject TEXT NOT NULL,
                        did TEXT NOT NULL,
                        otp_hash TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0
                    )
                """)

    def create_challenge(self, subject, did):

        challenge_id = secrets.token_urlsafe(32)

        otp = f"{secrets.randbelow(1000000):06d}"

        otp_hash = hashlib.sha256(
            f"{challenge_id}:{otp}".encode()
        ).hexdigest()

        expires_at = time.time() + self.otp_expiry_seconds

        with self.lock:
            with closing(self.get_connection()) as conn:
                with conn:
                    conn.execute("""
                        INSERT INTO mfa_challenges (
                            challenge_id,
                            subject,
                            did,
                            otp_hash,
                            expires_at,
                            attempts
                        )
                        VALUES (?, ?, ?, ?, ?, 0)
                    """, (
                        challenge_id,
                        subject,
                        did,
                        otp_hash,
                        expires_at
                    ))

        return {
            "challenge_id": challenge_id,
            "otp": otp
        }

    def verify_challenge(self, challenge_id, otp):

        with self.lock:
            with closing(self.get_connection()) as conn:

                # Prevent simultaneous verification requests
                # from using the same challenge.
                conn.execute("BEGIN IMMEDIATE")

                challenge = conn.execute("""
                    SELECT
                        subject,
                        did,
                        otp_hash,
                        expires_at,
                        attempts
                    FROM mfa_challenges
                    WHERE challenge_id = ?
                """, (challenge_id,)).fetchone()

                if challenge is None:
                    conn.commit()

                    return {
                        "valid": False,
                        "reason": "Invalid or expired challenge"
                    }

                subject, did, stored_hash, expires_at, attempts = challenge

                if time.time() > expires_at:
                    conn.execute("""
                        DELETE FROM mfa_challenges
                        WHERE challenge_id = ?
                    """, (challenge_id,))

                    conn.commit()

                    return {
                        "valid": False,
                        "reason": "OTP has expired"
                    }

                if attempts >= self.max_attempts:
                    conn.execute("""
                        DELETE FROM mfa_challenges
                        WHERE challenge_id = ?
                    """, (challenge_id,))

                    conn.commit()

                    return {
                        "valid": False,
                        "reason": "Maximum OTP attempts exceeded"
                    }

                supplied_hash = hashlib.sha256(
                    f"{challenge_id}:{otp}".encode()
                ).hexdigest()

                if not secrets.compare_digest(
                    supplied_hash,
                    stored_hash
                ):

                    new_attempts = attempts + 1

                    if new_attempts >= self.max_attempts:
                        conn.execute("""
                            DELETE FROM mfa_challenges
                            WHERE challenge_id = ?
                        """, (challenge_id,))

                        conn.commit()

                        return {
                            "valid": False,
                            "reason": "Maximum OTP attempts exceeded"
                        }

                    conn.execute("""
                        UPDATE mfa_challenges
                        SET attempts = ?
                        WHERE challenge_id = ?
                    """, (new_attempts, challenge_id))

                    conn.commit()

                    return {
                        "valid": False,
                        "reason": "Incorrect OTP",
                        "remaining_attempts": (
                            self.max_attempts - new_attempts
                        )
                    }

                # Correct OTP: delete the challenge so it
                # cannot be reused.
                conn.execute("""
                    DELETE FROM mfa_challenges
                    WHERE challenge_id = ?
                """, (challenge_id,))

                conn.commit()

                return {
                    "valid": True,
                    "subject": subject,
                    "did": did
                }


    def discard_challenge(self, challenge_id):

        """
        Delete a challenge when OTP delivery fails.
        """

        with self.lock:

            with closing(self.get_connection()) as conn:

                with conn:

                    conn.execute("""
                        DELETE FROM mfa_challenges
                        WHERE challenge_id = ?
                    """, (challenge_id,))


mfa_service = MFAService()