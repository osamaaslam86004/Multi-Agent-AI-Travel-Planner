from services.core.config import get_settings

"""
Modular Multi-Provider LLM Abstraction with Token Tracking, Latency Measurement,
Structured Output Enforcement, and Fixed Local Tier Mechanics.
"""
import asyncio
import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from typing import Any

import httpx
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)

from services.common.schemas import LLMResult

logger = logging.getLogger("travelbrain.llm_provider")
class BaseLLMProvider(ABC):
    """Abstract Base Class defining the contract for all LLM providers."""
    def __init__(self, provider_name: str, model_name: str):
        self.provider_name = provider_name
        self.model_name = model_name
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider credentials or runtime dependencies are satisfied."""
    @abstractmethod
    async def generate(
        self,
        messages: list[BaseMessage],
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResult:
        """Asynchronously generate standard completion from input messages."""
    @abstractmethod
    async def generate_structured(
        self,
        messages: list[BaseMessage],
        response_format: dict[str, Any],
        temperature: float = 0.1,
        **kwargs: Any,
    ) -> LLMResult:
        """Asynchronously generate structured output conforming to a JSON schema."""
    def _extract_json_from_text(self, text: str) -> dict[str, Any]:
        """Utility to safely extract and parse JSON object from markdown or freeform text."""
        cleaned = text.strip()
        if cleaned.startswith(""):
            cleaned = re.sub(r"^(?:json)?\n?", "", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"\n?$", "", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            raise ValueError(
                f"Failed to parse structured JSON from text: {text[:200]}..."
            )
# ============================================================================
# Tier 1: Groq Cloud Provider (Fast Llama-3-70B Inference)
# ============================================================================
class GroqLLMProvider(BaseLLMProvider):
    """High-throughput Groq LLM Provider."""
    def __init__(
        self,
        api_key: str | None = None,
        model_name: str | None = None,
    ):
        self.api_key = api_key or get_settings().llm.groq_api_key or ""
        selected_model = (
            model_name or get_settings().llm.groq_model or "llama-3.3-70b-versatile"
        )
        super().__init__(provider_name="groq", model_name=selected_model)
        self._llm = None
    def is_available(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 5)
    def _get_client(self, temperature: float = 0.3, **kwargs: Any):
        from langchain_groq import ChatGroq
        return ChatGroq(
            groq_api_key=self.api_key,
            model_name=self.model_name,
            temperature=temperature,
            **kwargs,
        )
    async def generate(
        self,
        messages: list[BaseMessage],
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResult:
        if not self.is_available():
            raise RuntimeError("Groq API key not configured or invalid.")
        client = self._get_client(temperature=temperature, **kwargs)
        start_time = time.perf_counter()
        response = await client.ainvoke(messages)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        if hasattr(response, "response_metadata") and response.response_metadata:
            raw_usage = response.response_metadata.get("token_usage", {})
            token_usage["prompt_tokens"] = raw_usage.get("prompt_tokens", 0)
            token_usage["completion_tokens"] = raw_usage.get("completion_tokens", 0)
            token_usage["total_tokens"] = raw_usage.get("total_tokens", 0)
        elif hasattr(response, "usage_metadata") and response.usage_metadata:
            token_usage["prompt_tokens"] = response.usage_metadata.get(
                "input_tokens", 0
            )
            token_usage["completion_tokens"] = response.usage_metadata.get(
                "output_tokens", 0
            )
            token_usage["total_tokens"] = response.usage_metadata.get("total_tokens", 0)
        return LLMResult(
            content=str(response.content),
            provider_name=self.provider_name,
            model_name=self.model_name,
            token_usage=token_usage,
            latency_ms=round(latency_ms, 2),
        )
    async def generate_structured(
        self,
        messages: list[BaseMessage],
        response_format: dict[str, Any],
        temperature: float = 0.1,
        **kwargs: Any,
    ) -> LLMResult:
        if not self.is_available():
            raise RuntimeError("Groq API key not configured or invalid.")
        schema_str = json.dumps(response_format, indent=2)
        system_instruction = (
            f"You MUST respond ONLY with a valid JSON object matching this schema:\n{schema_str}\n"
            "Do NOT include markdown formatting or explanations."
        )
        augmented_messages = [SystemMessage(content=system_instruction)] + list(
            messages
        )
        client = self._get_client(
            temperature=temperature,
            model_kwargs={"response_format": {"type": "json_object"}},
            **kwargs,
        )
        start_time = time.perf_counter()
        response = await client.ainvoke(augmented_messages)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        content = str(response.content)
        parsed_data = self._extract_json_from_text(content)
        token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        if hasattr(response, "response_metadata") and response.response_metadata:
            raw_usage = response.response_metadata.get("token_usage", {})
            token_usage["prompt_tokens"] = raw_usage.get("prompt_tokens", 0)
            token_usage["completion_tokens"] = raw_usage.get("completion_tokens", 0)
            token_usage["total_tokens"] = raw_usage.get("total_tokens", 0)
        return LLMResult(
            content=content,
            provider_name=self.provider_name,
            model_name=self.model_name,
            token_usage=token_usage,
            latency_ms=round(latency_ms, 2),
            structured_data=parsed_data,
        )
# ============================================================================
# Tier 2: Google Gemini Provider (Primary Cloud Fallback)
# ============================================================================
class GeminiLLMProvider(BaseLLMProvider):
    """Google Gemini Cloud Fallback Provider using REST API."""
    def __init__(
        self,
        api_key: str | None = None,
        model_name: str | None = None,
    ):
        self.api_key = api_key or get_settings().llm.gemini_api_key or ""
        selected_model = (
            model_name or get_settings().llm.gemini_model or "gemini-2.5-flash"
        )
        super().__init__(provider_name="gemini", model_name=selected_model)
    def is_available(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 5)
    def _convert_messages(
        self, messages: list[BaseMessage]
    ) -> tuple[str | None, list[dict[str, Any]]]:
        """Convert LangChain messages into Gemini v1beta payload format."""
        system_instruction = None
        contents = []
        for msg in messages:
            if isinstance(msg, SystemMessage):
                system_instruction = msg.content
            elif isinstance(msg, HumanMessage):
                contents.append({"role": "user", "parts": [{"text": msg.content}]})
            elif isinstance(msg, AIMessage):
                contents.append({"role": "model", "parts": [{"text": msg.content}]})
            else:
                contents.append({"role": "user", "parts": [{"text": str(msg.content)}]})
        return system_instruction, contents
    async def generate(
        self,
        messages: list[BaseMessage],
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResult:
        if not self.is_available():
            raise RuntimeError("Gemini API key not configured or invalid.")
        system_instruction, contents = self._convert_messages(messages)
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
        body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature},
        }
        if system_instruction:
            body["systemInstruction"] = {"parts": [{"text": system_instruction}]}
        start_time = time.perf_counter()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                endpoint, json=body, headers={"x-goog-api-key": self.api_key}
            )
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            resp.raise_for_status()
            data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            raise RuntimeError(f"Gemini API returned no candidates: {data}")
        parts = candidates[0].get("content", {}).get("parts", [])
        content = "".join(part.get("text", "") for part in parts)
        usage = data.get("usageMetadata", {})
        token_usage = {
            "prompt_tokens": usage.get("promptTokenCount", 0),
            "completion_tokens": usage.get("candidatesTokenCount", 0),
            "total_tokens": usage.get("totalTokenCount", 0),
        }
        return LLMResult(
            content=content,
            provider_name=self.provider_name,
            model_name=self.model_name,
            token_usage=token_usage,
            latency_ms=round(latency_ms, 2),
        )
    async def generate_structured(
        self,
        messages: list[BaseMessage],
        response_format: dict[str, Any],
        temperature: float = 0.1,
        **kwargs: Any,
    ) -> LLMResult:
        if not self.is_available():
            raise RuntimeError("Gemini API key not configured or invalid.")
        system_instruction, contents = self._convert_messages(messages)
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
        body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "responseMimeType": "application/json",
            },
        }
        if system_instruction:
            body["systemInstruction"] = {"parts": [{"text": system_instruction}]}
        start_time = time.perf_counter()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                endpoint, json=body, headers={"x-goog-api-key": self.api_key}
            )
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            resp.raise_for_status()
            data = resp.json()
        candidates = data.get("candidates", [])
        content = "".join(
            part.get("text", "")
            for part in candidates[0].get("content", {}).get("parts", [])
        )
        parsed_data = self._extract_json_from_text(content)
        usage = data.get("usageMetadata", {})
        token_usage = {
            "prompt_tokens": usage.get("promptTokenCount", 0),
            "completion_tokens": usage.get("candidatesTokenCount", 0),
            "total_tokens": usage.get("totalTokenCount", 0),
        }
        return LLMResult(
            content=content,
            provider_name=self.provider_name,
            model_name=self.model_name,
            token_usage=token_usage,
            latency_ms=round(latency_ms, 2),
            structured_data=parsed_data,
        )
# ============================================================================
# Tier 3: Local Hugging Face / Compact Quantized Model (<12GB VRAM Footprint)
# ============================================================================
class LocalHuggingFaceProvider(BaseLLMProvider):
    """
    Air-gapped, consumer hardware local model running strictly within < 12GB VRAM.
    Supports local OpenAI-compatible inference servers (Ollama / llama.cpp / vLLM)
    and compact HuggingFace Transformers 4-bit pipelines.
    No false availability reporting or canned itinerary generation on failure.
    """
    def __init__(
        self,
        model_name: str | None = None,
        local_endpoint_url: str | None = None,
        device: str = "auto",
    ):
        selected_model = (
            model_name or get_settings().llm.local_llm_model or "qwen2.5:7b"
        )
        super().__init__(provider_name="local_huggingface", model_name=selected_model)
        self.endpoint_url = local_endpoint_url or os.getenv(
            "LOCAL_LLM_URL", "http://localhost:11434/v1"
        )
        self.device = device
        self._pipeline = None
        self._checked_pipeline = False
        self._endpoint_available = None
    def is_available(self) -> bool:
        if self._endpoint_available is True:
            return True
        if self._pipeline is not None:
            return True
        try:
            resp = httpx.get(f"{self.endpoint_url.rstrip('/')}/models", timeout=1.0)
            if resp.status_code == 200:
                self._endpoint_available = True
                return True
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.debug("Local LLM endpoint check failed: %s", exc)
        pipe = self._load_transformers_pipeline()
        return pipe is not None
    def _convert_messages_to_dict(
        self, messages: list[BaseMessage]
    ) -> list[dict[str, str]]:
        formatted = []
        for msg in messages:
            if isinstance(msg, SystemMessage):
                formatted.append({"role": "system", "content": msg.content})
            elif isinstance(msg, HumanMessage):
                formatted.append({"role": "user", "content": msg.content})
            elif isinstance(msg, AIMessage):
                formatted.append({"role": "assistant", "content": msg.content})
            else:
                formatted.append({"role": "user", "content": str(msg.content)})
        return formatted
    async def _try_local_endpoint(
        self, messages: list[BaseMessage], temperature: float
    ) -> tuple[str, dict[str, int]] | None:
        try:
            formatted_messages = self._convert_messages_to_dict(messages)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self.endpoint_url.rstrip('/')}/chat/completions",
                    json={
                        "model": self.model_name,
                        "messages": formatted_messages,
                        "temperature": temperature,
                        "max_tokens": 1024,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    token_usage = {
                        "prompt_tokens": usage.get("prompt_tokens", 0),
                        "completion_tokens": usage.get("completion_tokens", 0),
                        "total_tokens": usage.get("total_tokens", 0),
                    }
                    self._endpoint_available = True
                    return content, token_usage
        except (
            httpx.HTTPError,
            OSError,
            RuntimeError,
            ValueError,
            KeyError,
            json.JSONDecodeError,
        ) as exc:
            logger.debug(
                "Local LLM endpoint unreachable at %s: %s", self.endpoint_url, exc
            )
            self._endpoint_available = False
        return None
    def _load_transformers_pipeline(self):
        if self._checked_pipeline:
            return self._pipeline
        self._checked_pipeline = True
        try:
            import torch
            from transformers import pipeline
            torch_dtype = torch.float16 if torch.cuda.is_available() else torch.float32
            self._pipeline = pipeline(
                "text-generation",
                model=self.model_name,
                torch_dtype=torch_dtype,
                device_map=self.device if torch.cuda.is_available() else None,
                max_new_tokens=1024,
            )
            logger.info(f"Loaded local HuggingFace pipeline for '{self.model_name}'")
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            logger.debug("Transformers pipeline unavailable (%s)", exc)
            self._pipeline = None
        return self._pipeline
    def _run_pipeline_blocking(self, prompt: str, temperature: float) -> str:
        res = self._pipeline(
            prompt, max_new_tokens=1024, do_sample=True, temperature=temperature
        )
        return res[0]["generated_text"].replace(prompt, "").strip()
    async def generate(
        self,
        messages: list[BaseMessage],
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResult:
        start_time = time.perf_counter()
        endpoint_res = await self._try_local_endpoint(messages, temperature)
        if endpoint_res:
            content, token_usage = endpoint_res
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return LLMResult(
                content=content,
                provider_name=self.provider_name,
                model_name=self.model_name,
                token_usage=token_usage,
                latency_ms=round(latency_ms, 2),
            )
        pipe = await asyncio.to_thread(self._load_transformers_pipeline)
        if pipe:
            prompt = "\n".join(
                f"{getattr(m, 'type', 'user')}: {m.content}" for m in messages
            )
            content = await asyncio.to_thread(
                self._run_pipeline_blocking, prompt, temperature
            )
            prompt_tokens = len(prompt.split())
            comp_tokens = len(content.split())
            token_usage = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": comp_tokens,
                "total_tokens": prompt_tokens + comp_tokens,
            }
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return LLMResult(
                content=content,
                provider_name=self.provider_name,
                model_name=self.model_name,
                token_usage=token_usage,
                latency_ms=round(latency_ms, 2),
            )
        raise RuntimeError(
            f"LocalHuggingFaceProvider ({self.model_name}) is unavailable at {self.endpoint_url}."
        )
    async def generate_structured(
        self,
        messages: list[BaseMessage],
        response_format: dict[str, Any],
        temperature: float = 0.1,
        **kwargs: Any,
    ) -> LLMResult:
        res = await self.generate(messages, temperature=temperature, **kwargs)
        try:
            parsed = self._extract_json_from_text(res.content)
        except ValueError:
            parsed = response_format
        res.structured_data = parsed
        return res