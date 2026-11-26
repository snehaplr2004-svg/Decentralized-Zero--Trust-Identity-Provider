
import hashlib
import secrets
import time
from threading import Lock


class MFAService:

    def __init__(self):
        self.challenges = {}
        self.lock = Lock()

        self.otp_expiry_seconds = 300
        self.max_attempts = 5

    def create_challenge(self, subject, did):

        challenge_id = secrets.token_urlsafe(32)

        otp = f"{secrets.randbelow(1000000):06d}"

        otp_hash = hashlib.sha256(
            f"{challenge_id}:{otp}".encode()
        ).hexdigest()

        with self.lock:
            self.challenges[challenge_id] = {
                "subject": subject,
                "did": did,
                "otp_hash": otp_hash,
                "expires_at": (
                    time.time() + self.otp_expiry_seconds
                ),
                "attempts": 0,
                "used": False
            }

        return {
            "challenge_id": challenge_id,
            "otp": otp
        }

    def verify_challenge(self, challenge_id, otp):

        with self.lock:

            challenge = self.challenges.get(
                challenge_id
            )

            if challenge is None:
                return {
                    "valid": False,
                    "reason": "Invalid or expired challenge"
                }

            if challenge["used"]:
                return {
                    "valid": False,
                    "reason": "Challenge already used"
                }

            if time.time() > challenge["expires_at"]:
                del self.challenges[challenge_id]

                return {
                    "valid": False,
                    "reason": "OTP has expired"
                }

            if challenge["attempts"] >= self.max_attempts:
                del self.challenges[challenge_id]

                return {
                    "valid": False,
                    "reason": "Maximum OTP attempts exceeded"
                }

            supplied_hash = hashlib.sha256(
                f"{challenge_id}:{otp}".encode()
            ).hexdigest()

            if not secrets.compare_digest(
                supplied_hash,
                challenge["otp_hash"]
            ):
                challenge["attempts"] += 1

                if challenge["attempts"] >= self.max_attempts:
                    del self.challenges[challenge_id]

                    return {
                        "valid": False,
                        "reason": "Maximum OTP attempts exceeded"
                    }

                return {
                    "valid": False,
                    "reason": "Incorrect OTP",
                    "remaining_attempts": (
                        self.max_attempts - challenge["attempts"]
                    )
                }

            challenge["used"] = True

            result = {
                "valid": True,
                "subject": challenge["subject"],
                "did": challenge["did"]
            }

            del self.challenges[challenge_id]

            return result


mfa_service = MFAService()
