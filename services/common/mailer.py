"""
Pluggable Mailer Interface & Delivery Adapters for TravelBrain.
Supports LogMailer (development/logging with masked token logging)
and SMTPMailer (non-blocking production delivery).
"""

import abc
import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from services.core.config import get_settings

logger = logging.getLogger("travelbrain.common.mailer")


def _mask_token_in_url(token_or_url: str) -> str:
    """Mask token material in URLs or raw tokens before logging to prevent secret leakage."""
    if not token_or_url:
        return ""
    if "token=" in token_or_url:
        base, token = token_or_url.rsplit("token=", 1)
        masked = token[:6] + "..." if len(token) > 6 else "***"
        return f"{base}token={masked}"
    masked = token_or_url[:6] + "..." if len(token_or_url) > 6 else "***"
    return masked


def build_absolute_url(path_or_url: str) -> str:
    """Construct an absolute URL targeting the configured public_base_url."""
    if not path_or_url:
        return get_settings().auth.public_base_url
    if path_or_url.startswith(("http://", "https://")):
        return path_or_url
    base = get_settings().auth.public_base_url.rstrip("/")
    path = path_or_url.lstrip("/")
    return f"{base}/{path}"


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

    @abc.abstractmethod
    async def send_invitation(
        self, email: str, token_or_url: str, org_id: str, role: str
    ) -> bool:
        pass


class LogMailer(MailerInterface):
    """Log-only Mailer Adapter for development and testing environments."""

    async def send_magic_link(self, email: str, token_or_url: str) -> bool:
        abs_url = build_absolute_url(token_or_url)
        logger.info(
            f"[LogMailer] Dispatching Magic Link to '{email}': {_mask_token_in_url(abs_url)}"
        )
        return True

    async def send_email_verification(self, email: str, token_or_url: str) -> bool:
        abs_url = build_absolute_url(token_or_url)
        logger.info(
            f"[LogMailer] Dispatching Email Verification to '{email}': {_mask_token_in_url(abs_url)}"
        )
        return True

    async def send_account_recovery(self, email: str, token_or_url: str) -> bool:
        abs_url = build_absolute_url(token_or_url)
        logger.info(
            f"[LogMailer] Dispatching Account Recovery Password Reset to '{email}': {_mask_token_in_url(abs_url)}"
        )
        return True

    async def send_invitation(
        self, email: str, token_or_url: str, org_id: str, role: str
    ) -> bool:
        abs_url = build_absolute_url(token_or_url)
        logger.info(
            f"[LogMailer] Dispatching Organization Invitation ({org_id}/{role}) to '{email}': {_mask_token_in_url(abs_url)}"
        )
        return True


class SMTPMailer(MailerInterface):
    """Production SMTP Delivery Adapter with non-blocking async execution."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        sender_email: str | None = None,
    ):
        settings = get_settings()
        self.host = host or getattr(settings.auth, "smtp_host", "smtp.travelbrain.ai")
        self.port = port or getattr(settings.auth, "smtp_port", 587)
        self.username = username or getattr(settings.auth, "smtp_username", "")
        self.password = password or getattr(settings.auth, "smtp_password", "")
        self.sender_email = sender_email or getattr(
            settings.auth,
            "smtp_from_email",
            getattr(settings.auth, "smtp_sender_email", "noreply@travelbrain.ai"),
        )

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
            with smtplib.SMTP(self.host, self.port, timeout=10.0) as server:
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
        abs_url = build_absolute_url(token_or_url)
        subject = "Your TravelBrain Secure Magic Link Login"
        body = f"Use the following secure link to log in to your account:\n\n{abs_url}\n\nThis link expires in 15 minutes."
        return await asyncio.to_thread(self._send_email_sync, email, subject, body)

    async def send_email_verification(self, email: str, token_or_url: str) -> bool:
        abs_url = build_absolute_url(token_or_url)
        subject = "Verify Your TravelBrain Account Email"
        body = f"Please verify your email address by clicking the link below:\n\n{abs_url}\n\nThis link expires in 24 hours."
        return await asyncio.to_thread(self._send_email_sync, email, subject, body)

    async def send_account_recovery(self, email: str, token_or_url: str) -> bool:
        abs_url = build_absolute_url(token_or_url)
        subject = "TravelBrain Account Password Reset & Recovery Request"
        body = f"A password reset request was initiated for your account.\n\nUse the link below to set a new password:\n\n{abs_url}\n\nThis link expires in 30 minutes."
        return await asyncio.to_thread(self._send_email_sync, email, subject, body)

    async def send_invitation(
        self, email: str, token_or_url: str, org_id: str, role: str
    ) -> bool:
        abs_url = build_absolute_url(token_or_url)
        subject = f"Invitation to Join Organization {org_id} on TravelBrain"
        body = f"You have been invited to join organization '{org_id}' with role '{role}'.\n\nUse the following link to accept your invitation:\n{abs_url}\n\nThis invitation expires in 7 days."
        return await asyncio.to_thread(self._send_email_sync, email, subject, body)


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


async def send_invitation_email(
    email: str, token_or_url: str, org_id: str, role: str
) -> bool:
    mailer = get_mailer()
    return await mailer.send_invitation(email, token_or_url, org_id, role)
