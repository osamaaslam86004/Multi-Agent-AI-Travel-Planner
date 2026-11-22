"""
Configuration Profile Validators & Fail-Fast Startup Checks.
Role-aware validation for background workers vs. API/Auth services.
"""

import logging
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from services.core.config.settings import Settings

logger = logging.getLogger("travelbrain.config.validators")


def _is_worker_process() -> bool:
    role = os.getenv("SERVICE_ROLE", "").lower()
    name = os.getenv("SERVICE_NAME", "").lower()
    cmd = " ".join(sys.argv).lower()
    return role == "worker" or "worker" in name or "worker" in cmd


def validate_profile_settings(settings: "Settings") -> None:
    env = settings.app.environment.lower()
    if env not in ("development", "staging", "production"):
        logger.warning(
            f"Unknown environment profile '{env}', defaulting to development validation."
        )
        return

    if env == "production":
        _validate_production(settings)
    elif env == "staging":
        _validate_staging(settings)
    else:
        _validate_development(settings)


def _validate_production(settings: "Settings") -> None:
    errors = []
    if settings.app.debug:
        errors.append("APP_DEBUG cannot be True in production profile.")

    # Role-aware validation: Workers do not require API auth secrets or RSA signing keys
    if not _is_worker_process():
        if "dev-jwt-key" in settings.auth.jwt_secret_key:
            errors.append(
                "JWT_SECRET_KEY is set to a default development value in production profile."
            )
        if "dev-scim" in settings.auth.scim_token_secret:
            errors.append(
                "SCIM_TOKEN_SECRET is set to a default development value in production profile."
            )
        if settings.auth.enable_dev_login:
            errors.append("ENABLE_DEV_LOGIN cannot be True in production profile.")
        priv_pem = settings.auth.jwt_private_key_pem or os.getenv("JWT_PRIVATE_KEY_PEM")
        priv_path = settings.auth.jwt_private_key_path or os.getenv(
            "JWT_PRIVATE_KEY_PATH"
        )
        if not priv_pem and not priv_path:
            errors.append(
                "RSA private key (JWT_PRIVATE_KEY_PEM or JWT_PRIVATE_KEY_PATH) is required in production profile."
            )
        if not settings.security.cookie_secure:
            errors.append("SECURITY_COOKIE_SECURE must be True in production profile.")
        if "*" in settings.security.cors_origins:
            errors.append(
                "SECURITY_CORS_ORIGINS cannot contain wildcard '*' in production profile."
            )

    if errors:
        errs_str = "\n".join(f"- {e}" for e in errors)
        error_msg = f"Fail-fast startup configuration check failed for PRODUCTION profile:\n{errs_str}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    logger.info("Production configuration profile successfully validated.")


def _validate_staging(settings: "Settings") -> None:
    errors = []
    if settings.app.debug:
        logger.warning("DEBUG mode is enabled in staging profile.")

    if not _is_worker_process():
        if settings.auth.enable_dev_login:
            errors.append("ENABLE_DEV_LOGIN cannot be True in staging profile.")
        priv_pem = settings.auth.jwt_private_key_pem or os.getenv("JWT_PRIVATE_KEY_PEM")
        priv_path = settings.auth.jwt_private_key_path or os.getenv(
            "JWT_PRIVATE_KEY_PATH"
        )
        if not priv_pem and not priv_path:
            logger.warning(
                "RSA private key is missing in staging profile; ephemeral key will be generated."
            )

    if errors:
        errs_str = "\n".join(f"- {e}" for e in errors)
        error_msg = f"Fail-fast startup configuration check failed for STAGING profile:\n{errs_str}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    logger.info("Staging configuration profile successfully validated.")


def _validate_development(settings: "Settings") -> None:
    logger.debug("Development configuration profile loaded with local defaults.")
