# src/config/session.py
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from src.config.settings import settings


@dataclass(frozen=True)
class Credentials:
    groq_api_key: str | None = None
    database_url: str | None = None


EMPTY = Credentials()
_current: ContextVar[Credentials] = ContextVar("travelbrain_credentials", default=EMPTY)


class MissingCredentialsError(RuntimeError):
    """Raised when a required key is configured in neither .env nor the session."""

    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__(
            "Missing credentials: "
            + ", ".join(missing)
            + ". Add them in Settings, or set them in the server's .env file."
        )


def get_credentials() -> Credentials:
    return _current.get()


@contextmanager
def use_credentials(credentials: Credentials | None):
    token = _current.set(credentials or EMPTY)
    try:
        yield
    finally:
        _current.reset(token)


# =========================
# Resolution
# =========================
def resolve_groq_api_key() -> str | None:
    session_key = get_credentials().groq_api_key
    if session_key:
        return session_key
    return settings.llm.groq_api_key.get_secret_value()


def resolve_database_url() -> str | None:
    session_url = get_credentials().database_url
    url = session_url or settings.db.url
    if url and "sslmode=" not in url:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}sslmode=require"
    return url


def require(*names: str) -> None:
    resolvers = {
        "GROQ_API_KEY": resolve_groq_api_key,
        "DATABASE_URL": resolve_database_url,
    }
    missing = [name for name in names if not resolvers[name]()]
    if missing:
        raise MissingCredentialsError(missing)


# =========================
# Status, for Settings UI
# =========================
CREDENTIAL_LABELS = {
    "GROQ_API_KEY": {
        "label": "Groq API key",
        "hint": "Powers every agent. Create one at console.groq.com/keys.",
        "placeholder": "gsk_...",
    },
    "DATABASE_URL": {
        "label": "PostgreSQL URL",
        "hint": "Stores LangGraph conversation checkpoints.",
        "placeholder": "postgresql://user:password@host:5432/dbname",
    },
}


def credential_status() -> dict:
    session = get_credentials()
    sources = {
        "GROQ_API_KEY": (
            "session"
            if session.groq_api_key
            else "env"
            if settings.llm.groq_api_key
            else None
        ),
        "DATABASE_URL": (
            "session" if session.database_url else "env" if settings.db.url else None
        ),
    }
    credentials = {
        name: {
            **CREDENTIAL_LABELS[name],
            "configured": source is not None,
            "source": source,
        }
        for name, source in sources.items()
    }
    missing = [name for name, source in sources.items() if source is None]
    return {
        "ready": not missing,
        "missing": missing,
        "credentials": credentials,
    }
