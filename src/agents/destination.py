# src/agents/destination.py
"""Pulls the destination out of a free-form travel query."""

from src.agents.prompts import DESTINATION_EXTRACTION_PROMPT
from src.clients.cache import cached
from src.clients.llm import get_llm
from src.config.settings import settings


@cached(prefix="destination", ttl=settings.redis.ttl_destination)
def extract_destination(query: str) -> str:
    """
    Cached: the same query always maps to the same destination, so this
    LLM call is pure overhead on a repeat.
    """
    prompt = DESTINATION_EXTRACTION_PROMPT.format(query=query)
    response = get_llm().invoke(prompt)
    return response.content.strip()
