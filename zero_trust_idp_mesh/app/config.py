import os
from pathlib import Path
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent

# Load private settings from the project-root .env file.
load_dotenv(BASE_DIR / ".env")


class Settings:

    def __init__(self):

        self.environment = os.getenv(
            "APP_ENV",
            "development"
        ).lower()

        self.expose_development_otp = (
            self.environment == "development"
            and os.getenv(
                "EXPOSE_DEVELOPMENT_OTP",
                "true"
            ).lower() == "true"
        )

        self.email_mfa_enabled = (
            os.getenv(
                "EMAIL_MFA_ENABLED",
                "false"
            ).lower() == "true"
        )

        self.smtp_host = os.getenv(
            "SMTP_HOST",
            "smtp.gmail.com"
        )

        self.smtp_port = int(
            os.getenv("SMTP_PORT", "587")
        )

        self.smtp_username = os.getenv(
            "SMTP_USERNAME",
            ""
        )

        self.smtp_password = os.getenv(
            "SMTP_PASSWORD",
            ""
        )

        self.email_from = os.getenv(
            "EMAIL_FROM",
            self.smtp_username
        )

    @property
    def is_production(self):
        return self.environment == "production"

    @property
    def smtp_configured(self):
        return all([
            self.smtp_host,
            self.smtp_port,
            self.smtp_username,
            self.smtp_password,
            self.email_from
        ])


settings = Settings()