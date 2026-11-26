import smtplib
import ssl

from email.message import EmailMessage

from .config import settings


def send_otp_email(recipient, otp):

    if not settings.smtp_configured:
        raise RuntimeError(
            "Gmail SMTP configuration is incomplete"
        )

    if not recipient or not otp:
        raise ValueError(
            "Recipient and OTP are required"
        )

    message = EmailMessage()

    message["Subject"] = "Your Identity Provider MFA Code"
    message["From"] = settings.email_from
    message["To"] = recipient

    message.set_content(
        f"""
Hello,

Your verification code is:

{otp}

This code expires in 5 minutes.

You can use this code only once.

If you did not request this verification,
please ignore this email.

Regards,
Zero-Trust Identity Provider Mesh
"""
    )

    context = ssl.create_default_context()

    with smtplib.SMTP(
        settings.smtp_host,
        settings.smtp_port,
        timeout=15
    ) as server:

        server.ehlo()

        server.starttls(context=context)

        server.ehlo()

        server.login(
            settings.smtp_username,
            settings.smtp_password
        )

        server.send_message(message)

    return True