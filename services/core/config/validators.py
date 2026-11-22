"""
Configuration Profile Validators & Fail-Fast Startup Checks.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from services.core.config.settings import Settings

logger = logging.getLogger("travelbrain.config.validators")


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

    if "dev-jwt-key" in settings.auth.jwt_secret_key:
        errors.append(
            "JWT secret key is set to a default development value in production profile."
        )

    if errors:
        error_msg = (
            "Fail-fast startup configuration check failed for PRODUCTION profile:\n"
            + "\n".join(f"- {e}" for e in errors)
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    logger.info("Production configuration profile successfully validated.")


def _validate_staging(settings: "Settings") -> None:
    if settings.app.debug:
        logger.warning("DEBUG mode is enabled in staging profile.")
    logger.info("Staging configuration profile successfully validated.")


def _validate_development(settings: "Settings") -> None:
    logger.debug("Development configuration profile loaded with local defaults.")
