"""Standardized LLM provider interfaces and implementations isolating vendor client logic."""

from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any

from langchain_core.messages import AnyMessage, BaseMessage
from langchain_groq import ChatGroq

from src.config.session import require, resolve_groq_api_key
from src.config.settings import settings


class BaseLLMProvider(ABC):
    """Abstract base provider isolating LLM vendor and client interaction logic."""

    @abstractmethod
    def invoke(self, messages: list[BaseMessage] | str, **kwargs: Any) -> AnyMessage:
        """Invoke the underlying LLM provider synchronously."""

    @abstractmethod
    async def ainvoke(
        self, messages: list[BaseMessage] | str, **kwargs: Any
    ) -> AnyMessage:
        """Invoke the underlying LLM provider asynchronously."""

    @abstractmethod
    def get_client(self) -> Any:
        """Retrieve the underlying model client instance."""


class GroqLLMProvider(BaseLLMProvider):
    """Concrete Groq LLM Provider implementation."""

    def __init__(
        self, model_name: str | None = None, api_key: str | None = None
    ) -> None:
        self.model_name = model_name or settings.llm.model
        self._explicit_api_key = api_key

    def _resolve_client(self) -> ChatGroq:
        require("GROQ_API_KEY")
        api_key = self._explicit_api_key or resolve_groq_api_key()
        return _cached_groq_client(self.model_name, api_key)

    def get_client(self) -> ChatGroq:
        return self._resolve_client()

    def invoke(self, messages: list[BaseMessage] | str, **kwargs: Any) -> AnyMessage:
        client = self.get_client()
        return client.invoke(messages, **kwargs)

    async def ainvoke(
        self, messages: list[BaseMessage] | str, **kwargs: Any
    ) -> AnyMessage:
        client = self.get_client()
        return await client.ainvoke(messages, **kwargs)


@lru_cache(maxsize=8)
def _cached_groq_client(model: str, api_key: str) -> ChatGroq:
    """Cached ChatGroq client factory preventing redundant client reinstantiations."""
    return ChatGroq(model=model, api_key=api_key)


class LLMProviderRegistry:
    """Registry managing available LLM providers."""

    def __init__(self) -> None:
        self._providers: dict[str, BaseLLMProvider] = {}
        # Pre-register default Groq provider
        self._providers["groq"] = GroqLLMProvider()

    def get(self, name: str = "groq") -> BaseLLMProvider:
        if name not in self._providers:
            raise KeyError(f"LLM Provider '{name}' not found.")
        return self._providers[name]

    def register(self, name: str, provider: BaseLLMProvider) -> None:
        self._providers[name] = provider


default_llm_provider_registry = LLMProviderRegistry()


def get_llm_provider(name: str = "groq") -> BaseLLMProvider:
    """Retrieve an LLM provider instance from the registry."""
    return default_llm_provider_registry.get(name)
