# src/clients/llm.py
from functools import lru_cache

from langchain_groq import ChatGroq

from src.config.session import require, resolve_groq_api_key
from src.config.settings import settings


@lru_cache(maxsize=8)
def _build_llm(model: str, api_key: str) -> ChatGroq:
    return ChatGroq(model=model, api_key=api_key)


def get_llm() -> ChatGroq:
    """Resolves Groq LLM client instance per session or environment key."""
    require("GROQ_API_KEY")
    return _build_llm(settings.llm.model, resolve_groq_api_key())
