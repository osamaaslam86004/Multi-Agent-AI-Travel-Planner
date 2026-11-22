"""
LLM Providers Domain Settings.
"""

from pydantic import Field

from services.core.config.base import BaseDomainSettings


class LLMSettings(BaseDomainSettings):
    primary_provider: str = Field(default="groq", description="groq, gemini, or local")
    fallback_chain: list[str] = Field(
        default_factory=lambda: ["groq", "gemini", "local"]
    )
    groq_api_key: str | None = None
    groq_model: str = "llama-3.3-70b-versatile"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"
    local_llm_model: str = "qwen2.5:7b"
    local_llm_base_url: str = "http://localhost:11434/v1"
    timeout_seconds: float = 30.0
    max_retries: int = 3
    finops_daily_token_budget: int = 1000000

    @classmethod
    def load(cls) -> "LLMSettings":
        aliases = {
            "primary_provider": "LLM_PRIMARY_PROVIDER",
            "groq_api_key": "GROQ_API_KEY",
            "groq_model": "GROQ_MODEL",
            "gemini_api_key": "GEMINI_API_KEY",
            "gemini_model": "GEMINI_MODEL",
            "local_llm_model": "LOCAL_LLM_MODEL",
            "local_llm_base_url": "LOCAL_LLM_BASE_URL",
        }
        return cls.load_from_env(prefix="LLM", aliases=aliases)
