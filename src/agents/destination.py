"""Pulls the destination out of a free-form travel query using prompt registry and telemetry."""

from src.agents.prompts_registry import default_prompt_registry
from src.clients.cache import cached
from src.clients.llm_provider import get_llm_provider
from src.config.settings import settings
from src.utils.telemetry import track_performance


@cached(prefix="destination", ttl=settings.redis.ttl_destination)
@track_performance("extract_destination")
def extract_destination(query: str) -> str:
    """
    Cached: the same query always maps to the same destination.
    """
    prompt = default_prompt_registry.format_prompt(
        "destination_extraction", query=query
    )
    llm_provider = get_llm_provider("groq")
    response = llm_provider.invoke(prompt)
    return response.content.strip()
