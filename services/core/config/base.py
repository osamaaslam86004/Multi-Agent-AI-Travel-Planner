"""
Base configuration settings engine built on Pydantic v2 with environment variable parsing,
aliases, profile management, and validation.
"""

import os
from typing import Any, Self, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound="BaseDomainSettings")


class BaseDomainSettings(BaseModel):
    """
    Base domain settings model. Automatically populates fields from environment variables
    matching field names or explicit aliases, with support for environment prefixes.
    """

    model_config = {
        "arbitrary_types_allowed": True,
        "populate_by_name": True,
        "extra": "ignore",
    }

    @classmethod
    @classmethod
    def load_from_env(
        cls, prefix: str = "", aliases: dict[str, str] | None = None
    ) -> Self:
        """
        Instantiate settings model reading from os.environ.
        Order of lookup for a field 'foo':
        1. Explicit alias in `aliases` map (e.g. 'REDIS_URL')
        2. Uppercase prefixed field name (e.g. 'TB_REDIS_URL')
        3. Uppercase field name (e.g. 'URL')
        """
        aliases = aliases or {}
        data: dict[str, Any] = {}

        for field_name, field_info in cls.model_fields.items():
            env_val = None

            # 1. Check explicit alias mapping
            alias_key = aliases.get(field_name)
            if alias_key and os.getenv(alias_key) is not None:
                env_val = os.getenv(alias_key)

            # 2. Check prefixed environment variable
            if env_val is None and prefix:
                prefixed_key = f"{prefix}_{field_name}".upper()
                if os.getenv(prefixed_key) is not None:
                    env_val = os.getenv(prefixed_key)

            # 3. Check exact field name uppercase
            if env_val is None:
                exact_key = field_name.upper()
                if os.getenv(exact_key) is not None:
                    env_val = os.getenv(exact_key)

            if env_val is not None:
                # Type conversion for basic types
                annotation = field_info.annotation
                if annotation is int or annotation is (int | None):
                    try:
                        data[field_name] = int(env_val)
                    except ValueError:
                        data[field_name] = env_val
                elif annotation is float or annotation is (float | None):
                    try:
                        data[field_name] = float(env_val)
                    except ValueError:
                        data[field_name] = env_val
                elif annotation is bool or annotation is (bool | None):
                    data[field_name] = env_val.lower() in ("true", "1", "yes", "on")
                elif annotation is list[str] or annotation is (list[str] | None):
                    if isinstance(env_val, str):
                        data[field_name] = [
                            item.strip() for item in env_val.split(",") if item.strip()
                        ]
                    else:
                        data[field_name] = env_val
                else:
                    data[field_name] = env_val

        return cls(**data)
