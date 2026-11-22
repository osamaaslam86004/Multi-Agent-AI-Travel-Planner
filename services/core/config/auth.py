"""
Authentication & Enterprise Identity Domain Settings.
"""

from pydantic import Field

from services.core.config.base import BaseDomainSettings


class AuthSettings(BaseDomainSettings):
    # Core JWT Settings
    jwt_secret_key: str = Field(
        default="dev-jwt-key-change-in-production-32chars", min_length=16
    )
    jwt_algorithm: str = "RS256"
    jwt_issuer: str = "https://auth.travelbrain.ai"
    jwt_audience: str = "https://api.travelbrain.ai"
    access_token_expire_seconds: int = 3600
    refresh_token_expire_seconds: int = 604800
    sudo_token_expire_seconds: int = 900

    # Core Auth Service URLs
    auth_service_url: str = "http://auth-service:8001"
    auth_service_jwks_url: str = "http://auth-service:8001/.well-known/jwks.json"
    jwt_previous_private_key_path: str | None = None
    jwt_previous_private_key_pem: str | None = None

    # OAuth / OIDC Providers Config
    google_client_id: str | None = None
    google_client_secret: str | None = None

    entra_client_id: str | None = None
    entra_client_secret: str | None = None
    entra_tenant_id: str = "common"

    github_client_id: str | None = None
    github_client_secret: str | None = None

    generic_oidc_issuer: str | None = None
    generic_oidc_client_id: str | None = None
    generic_oidc_client_secret: str | None = None

    # Enterprise Identity & SAML 2.0
    saml_sp_entity_id: str = "https://auth.travelbrain.ai/saml/metadata"
    saml_acs_url: str = "https://auth.travelbrain.ai/api/v1/auth/saml/acs"
    scim_token_secret: str = "dev-scim-token-secret-32chars-key"

    # Security & Auth Policies
    min_password_length: int = 12
    require_mfa_for_admins: bool = True
    max_failed_login_attempts: int = 5
    lockout_duration_seconds: int = 900
    enforce_device_trust: bool = False
    enable_suspicious_login_detection: bool = True

    @classmethod
    def load(cls) -> "AuthSettings":
        aliases = {
            "jwt_secret_key": "JWT_SECRET_KEY",
            "jwt_algorithm": "JWT_ALGORITHM",
            "jwt_issuer": "JWT_ISSUER",
            "jwt_audience": "JWT_AUDIENCE",
            "access_token_expire_seconds": "ACCESS_TOKEN_EXPIRE_SECONDS",
            "refresh_token_expire_seconds": "REFRESH_TOKEN_EXPIRE_SECONDS",
            "sudo_token_expire_seconds": "SUDO_TOKEN_EXPIRE_SECONDS",
            "google_client_id": "GOOGLE_CLIENT_ID",
            "google_client_secret": "GOOGLE_CLIENT_SECRET",
            "entra_client_id": "ENTRA_CLIENT_ID",
            "entra_client_secret": "ENTRA_CLIENT_SECRET",
            "entra_tenant_id": "ENTRA_TENANT_ID",
            "github_client_id": "GITHUB_CLIENT_ID",
            "github_client_secret": "GITHUB_CLIENT_SECRET",
            "generic_oidc_issuer": "GENERIC_OIDC_ISSUER",
            "generic_oidc_client_id": "GENERIC_OIDC_CLIENT_ID",
            "generic_oidc_client_secret": "GENERIC_OIDC_CLIENT_SECRET",
            "saml_sp_entity_id": "SAML_SP_ENTITY_ID",
            "saml_acs_url": "SAML_ACS_URL",
            "scim_token_secret": "SCIM_TOKEN_SECRET",
            "min_password_length": "MIN_PASSWORD_LENGTH",
            "require_mfa_for_admins": "REQUIRE_MFA_FOR_ADMINS",
            "max_failed_login_attempts": "MAX_FAILED_LOGIN_ATTEMPTS",
            "lockout_duration_seconds": "LOCKOUT_DURATION_SECONDS",
            "enforce_device_trust": "ENFORCE_DEVICE_TRUST",
            "enable_suspicious_login_detection": "ENABLE_SUSPICIOUS_LOGIN_DETECTION",
            "auth_service_url": "AUTH_SERVICE_URL",
            "auth_service_jwks_url": "AUTH_SERVICE_JWKS_URL",
            "jwt_previous_private_key_path": "JWT_PREVIOUS_PRIVATE_KEY_PATH",
            "jwt_previous_private_key_pem": "JWT_PREVIOUS_PRIVATE_KEY_PEM",
        }
        return cls.load_from_env(prefix="AUTH", aliases=aliases)
