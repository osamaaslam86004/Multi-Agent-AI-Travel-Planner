"""
Authentication Domain Settings.
"""

from pydantic import Field

from services.core.config.base import BaseDomainSettings


class AuthSettings(BaseDomainSettings):
    jwt_secret_key: str = Field(
        default="dev-jwt-key-change-in-production-32chars", min_length=16
    )
    jwt_algorithm: str = "RS256"
    jwt_issuer: str = "https://auth.travelbrain.ai"
    jwt_audience: str = "https://api.travelbrain.ai"
    access_token_expire_seconds: int = 3600
    refresh_token_expire_seconds: int = 604800
    google_client_id: str | None = None
    google_client_secret: str | None = None
    auth_service_url: str = "http://auth-service:8001"
    auth_service_jwks_url: str = "http://auth-service:8001/.well-known/jwks.json"
    jwt_previous_private_key_path: str | None = None
    jwt_previous_private_key_pem: str | None = None

    @classmethod
    def load(cls) -> "AuthSettings":
        aliases = {
            "jwt_secret_key": "JWT_SECRET_KEY",
            "jwt_algorithm": "JWT_ALGORITHM",
            "jwt_issuer": "JWT_ISSUER",
            "jwt_audience": "JWT_AUDIENCE",
            "access_token_expire_seconds": "ACCESS_TOKEN_EXPIRE_SECONDS",
            "refresh_token_expire_seconds": "REFRESH_TOKEN_EXPIRE_SECONDS",
            "google_client_id": "GOOGLE_CLIENT_ID",
            "google_client_secret": "GOOGLE_CLIENT_SECRET",
            "auth_service_url": "AUTH_SERVICE_URL",
            "auth_service_jwks_url": "AUTH_SERVICE_JWKS_URL",
            "jwt_previous_private_key_path": "JWT_PREVIOUS_PRIVATE_KEY_PATH",
            "jwt_previous_private_key_pem": "JWT_PREVIOUS_PRIVATE_KEY_PEM",
        }
        return cls.load_from_env(prefix="AUTH", aliases=aliases)
