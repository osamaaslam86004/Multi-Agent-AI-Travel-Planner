"""
Feature Flags Domain Settings.
"""
from services.core.config.base import BaseDomainSettings


class FeatureFlagSettings(BaseDomainSettings):
    enable_llm_failover: bool = True
    enable_pii_redaction: bool = True
    enable_circuit_breaker: bool = True
    enable_stream_caching: bool = True
    enable_mcp_integrations: bool = True
    enable_experimental_agents: bool = False
    @classmethod
    def load(cls) -> "FeatureFlagSettings":
        aliases = {
            "enable_llm_failover": "ENABLE_LLM_FAILOVER",
            "enable_pii_redaction": "ENABLE_PII_REDACTION",
            "enable_circuit_breaker": "ENABLE_CIRCUIT_BREAKER",
            "enable_stream_caching": "ENABLE_STREAM_CACHING",
            "enable_mcp_integrations": "ENABLE_MCP_INTEGRATIONS",
        }
        return cls.load_from_env(prefix="FF", aliases=aliases)