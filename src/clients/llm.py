"""Resolves Groq LLM client instance per session or environment key."""

from src.clients.llm_provider import get_llm_provider


def get_llm():
    """Resolves Groq LLM client instance per session or environment key."""
    provider = get_llm_provider("groq")
    return provider.get_client()
