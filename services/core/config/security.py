"""
Security Domain Settings.
"""

from pydantic import Field

from services.core.config.base import BaseDomainSettings


class SecuritySettings(BaseDomainSettings):
    session_cookie_name: str = "tb_session"
    csrf_header_name: str = "x-csrf-token"
    cookie_secure: bool = False
    cookie_httponly: bool = True
    cookie_samesite: str = "lax"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["*"])

    @classmethod
    def load(cls) -> "SecuritySettings":
        aliases = {
            "session_cookie_name": "SESSION_COOKIE_NAME",
            "csrf_header_name": "CSRF_HEADER_NAME",
            "cookie_secure": "COOKIE_SECURE",
        }
        return cls.load_from_env(prefix="SECURITY", aliases=aliases)
