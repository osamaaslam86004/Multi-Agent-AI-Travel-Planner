"""
Pluggable Mailer Interface & Delivery Adapters for TravelBrain.
Supports LogMailer (development/logging) and SMTPMailer (production delivery).
"""

import abc
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from services.core.config import get_settings

logger = logging.getLogger("travelbrain.common.mailer")


class MailerInterface(abc.ABC):
    """Abstract Mailer Interface for sending transactional identity emails."""

    @abc.abstractmethod
    async def send_magic_link(self, email: str, token_or_url: str) -> bool:
        pass

    @abc.abstractmethod
    async def send_email_verification(self, email: str, token_or_url: str) -> bool:
        pass

    @abc.abstractmethod
    async def send_account_recovery(self, email: str, token_or_url: str) -> bool:
        pass


class LogMailer(MailerInterface):
    """Log-only Mailer Adapter for development and testing environments."""

    async def send_magic_link(self, email: str, token_or_url: str) -> bool:
        logger.info(f"[LogMailer] Dispatching Magic Link to '{email}': {token_or_url}")
        return True

    async def send_email_verification(self, email: str, token_or_url: str) -> bool:
        logger.info(
            f"[LogMailer] Dispatching Email Verification to '{email}': {token_or_url}"
        )
        return True

    async def send_account_recovery(self, email: str, token_or_url: str) -> bool:
        logger.info(
            f"[LogMailer] Dispatching Account Recovery Password Reset to '{email}': {token_or_url}"
        )
        return True


class SMTPMailer(MailerInterface):
    """Production SMTP Delivery Adapter."""

    def __init__(
        self,
        host: str = "smtp.travelbrain.ai",
        port: int = 587,
        username: str = "",
        password: str = "",
        sender_email: str = "noreply@travelbrain.ai",
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sender_email = sender_email

    def _send_email_sync(
        self, recipient: str, subject: str, body_text: str, body_html: str | None = None
    ) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.sender_email
            msg["To"] = recipient

            msg.attach(MIMEText(body_text, "plain"))
            if body_html:
                msg.attach(MIMEText(body_html, "html"))

            with smtplib.SMTP(self.host, self.port) as server:
                server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.sender_email, [recipient], msg.as_string())
            logger.info(f"[SMTPMailer] Email successfully dispatched to '{recipient}'")
            return True
        except Exception as exc:
            logger.error(f"[SMTPMailer] Failed to send email to '{recipient}': {exc}")
            return False

    async def send_magic_link(self, email: str, token_or_url: str) -> bool:
        subject = "Your TravelBrain Secure Magic Link Login"
        body = f"Use the following secure link to log in to your account:\n\n{token_or_url}\n\nThis link expires in 15 minutes."
        return self._send_email_sync(email, subject, body)

    async def send_email_verification(self, email: str, token_or_url: str) -> bool:
        subject = "Verify Your TravelBrain Account Email"
        body = f"Please verify your email address by clicking the link below:\n\n{token_or_url}\n\nThis link expires in 24 hours."
        return self._send_email_sync(email, subject, body)

    async def send_account_recovery(self, email: str, token_or_url: str) -> bool:
        subject = "TravelBrain Account Password Reset & Recovery Request"
        body = f"A password reset request was initiated for your account.\n\nUse the link below to set a new password:\n\n{token_or_url}\n\nThis link expires in 30 minutes."
        return self._send_email_sync(email, subject, body)


_mailer_instance: MailerInterface | None = None


def get_mailer() -> MailerInterface:
    global _mailer_instance
    if _mailer_instance is None:
        env = get_settings().app.environment.lower()
        if env == "production":
            _mailer_instance = SMTPMailer()
        else:
            _mailer_instance = LogMailer()
    return _mailer_instance
