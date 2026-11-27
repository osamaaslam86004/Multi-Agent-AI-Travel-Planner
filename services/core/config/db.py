"""
Database Domain Settings.
"""

from pydantic import Field

from services.core.config.base import BaseDomainSettings


class DatabaseSettings(BaseDomainSettings):
    host: str = Field(default="localhost", description="PostgreSQL host")
    port: int = Field(default=5432, description="PostgreSQL port")
    db_name: str = Field(default="travelbrain", description="PostgreSQL database name")
    user: str = Field(default="travelbrain", description="PostgreSQL user")
    password: str = Field(
        default="travelbrain_pg_pass_2026", description="PostgreSQL password"
    )
    pool_min_size: int = 2
    pool_max_size: int = 10
    pool_timeout_seconds: float = 30.0
    ssl_mode: str = "prefer"
    statement_timeout_ms: int = 10000

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.db_name}"

    @classmethod
    def load(cls) -> "DatabaseSettings":
        aliases = {
            "host": "POSTGRES_HOST",
            "port": "POSTGRES_PORT",
            "db_name": "POSTGRES_DB",
            "user": "POSTGRES_USER",
            "password": "POSTGRES_PASSWORD",
            "pool_min_size": "POSTGRES_POOL_MIN",
            "pool_max_size": "POSTGRES_POOL_MAX",
        }
        return cls.load_from_env(prefix="POSTGRES", aliases=aliases)
