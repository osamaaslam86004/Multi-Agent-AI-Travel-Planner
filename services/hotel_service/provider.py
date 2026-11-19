"""
Hotel Provider with 3-Tier Fallback Architecture:
Tier 1: Tavily Search API (Primary)
Tier 2: DuckDuckGo MCP Server via stdio (Secondary)
Tier 3: Static Accommodation Heuristics (Tertiary Guaranteed Fallback)
"""

import asyncio
import hashlib
import json
import logging
import os
from typing import Any

import redis.asyncio as aioredis
from langchain_mcp_adapters.client import MultiServerMCPClient
from tavily import TavilyClient

from services.common.resilience import CircuitBreaker
from services.common.schemas import ProviderResult

logger = logging.getLogger("travelbrain.hotel_service")

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/2")
DUCKDUCKGO_MCP_COMMAND = os.getenv("DUCKDUCKGO_MCP_COMMAND", "duckduckgo-mcp")

tavily_breaker = CircuitBreaker("TavilyHotelBreaker", fail_max=3, reset_timeout=30.0)
mcp_breaker = CircuitBreaker("DuckDuckGoMCPBreaker", fail_max=3, reset_timeout=20.0)

APPROVED_HOTEL_TOOLS = {"duckduckgo_search", "ddg_search", "search", "web_search"}


class HotelProvider:
    """Manages accommodation searches via a 3-Tier Enterprise Fallback Architecture."""

    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._redis: aioredis.Redis | None = None
        self._mcp_client: MultiServerMCPClient | None = None
        self.tavily_breaker = tavily_breaker
        self.mcp_breaker = mcp_breaker

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis

    async def get_mcp_client(self) -> MultiServerMCPClient:
        if self._mcp_client is None:
            cmd = DUCKDUCKGO_MCP_COMMAND
            args_env = os.getenv("DUCKDUCKGO_MCP_ARGS", "")
            args = args_env.split() if args_env else []
            server_config = {
                "duckduckgo": {
                    "command": cmd,
                    "args": args,
                    "transport": "stdio",
                }
            }
            self._mcp_client = MultiServerMCPClient(server_config)
        return self._mcp_client

    async def close(self) -> None:
        if self._mcp_client is not None:
            for method in ("close", "aclose"):
                if hasattr(self._mcp_client, method):
                    try:
                        res = getattr(self._mcp_client, method)()
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception as exc:
                        logger.warning("Error closing hotel MCP client: %s", exc)
                    break
            self._mcp_client = None
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None

    def _cache_key(self, query: str, destination: str | None = None) -> str:
        raw = f"{query.strip().lower()}:{destination or ''}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return f"hotel:cache:{h}"

    async def search_hotels(
        self,
        query: str,
        destination: str | None = None,
        dates: str | None = None,
    ) -> ProviderResult:
        """High-level hotel search with Redis caching and 3-Tier failover execution."""
        r = await self.get_redis()
        cache_key = self._cache_key(query, destination)
        cached_data = await r.get(cache_key)
        if cached_data:
            logger.info(f"Hotel cache hit for query: '{query}'")
            return ProviderResult(**json.loads(cached_data))

        target_location = destination or query
        results = await self._execute_tiered_search(target_location)

        # Cache discipline: Do not cache degraded fallback results for 12h
        if not results.degraded:
            await r.setex(cache_key, 43200, json.dumps(results.model_dump()))
        else:
            await r.setex(cache_key, 60, json.dumps(results.model_dump()))

        return results

    async def _execute_tiered_search(self, target_location: str) -> ProviderResult:
        """Orchestrates sequential failover across Tier 1 (Tavily), Tier 2 (DuckDuckGo MCP), and Tier 3 (Fallback)."""
        # Tier 1 — Primary Provider (Tavily API)
        try:
            logger.info(
                f"Attempting Tier 1 (Tavily API) hotel search for: '{target_location}'"
            )
            text = await self.tavily_breaker.call(
                self._fetch_tavily_hotels, target_location
            )
            return ProviderResult(text=text, source="tavily", degraded=False)
        except Exception as exc:
            logger.warning(
                f"Tier 1 (Tavily API) failed for '{target_location}': {exc}. Failing over to Tier 2 (DuckDuckGo MCP)..."
            )

        # Tier 2 — Secondary Fallback (DuckDuckGo MCP Server)
        try:
            logger.info(
                f"Attempting Tier 2 (DuckDuckGo MCP Server) hotel search for: '{target_location}'"
            )
            text = await self.mcp_breaker.call(
                self._fetch_duckduckgo_mcp, target_location
            )
            return ProviderResult(text=text, source="duckduckgo_mcp", degraded=False)
        except Exception as exc:
            logger.warning(
                f"Tier 2 (DuckDuckGo MCP) failed for '{target_location}': {exc}. Failing over to Tier 3 (Fallback)..."
            )

        # Tier 3 — Tertiary Fallback (Static Heuristics)
        logger.info(f"Executing Tier 3 (Fallback) for: '{target_location}'")
        return self._fallback_hotels(target_location)

    async def _fetch_tavily_hotels(self, location: str) -> str:
        """Call Tavily search API asynchronously without blocking event loop."""
        if not TAVILY_API_KEY:
            raise ValueError("Tavily API key not configured")

        def _sync_search():
            client = TavilyClient(api_key=TAVILY_API_KEY)
            return client.search(
                query=f"Best recommended hotels accommodations in {location}",
                search_depth="advanced",
                max_results=5,
            )

        response = await asyncio.to_thread(_sync_search)

        snippets = [
            f"- {item.get('title')}: {item.get('content')}"
            for item in response.get("results", [])
            if item.get("title") or item.get("content")
        ]
        res_text = "\n".join(snippets).strip()
        if not res_text:
            raise RuntimeError("Tavily API returned empty hotel results")
        return res_text

    async def _fetch_duckduckgo_mcp(self, location: str) -> str:
        """Secondary fallback: Connect to DuckDuckGo MCP Server via stdio and execute search."""
        search_query = f"Best recommended hotels accommodations in {location}"

        async with asyncio.timeout(10.0):
            client = await self.get_mcp_client()
            tools = await client.get_tools()
            if not tools:
                raise RuntimeError("No tools discovered from DuckDuckGo MCP server")

            matching_tools = [
                t
                for t in tools
                if getattr(t, "name", "").lower() in APPROVED_HOTEL_TOOLS
            ]
            if not matching_tools:
                matching_tools = [
                    t
                    for t in tools
                    if any(
                        kw in getattr(t, "name", "").lower()
                        for kw in ("search", "ddg", "duck")
                    )
                ]
            if not matching_tools:
                raise RuntimeError(
                    "No approved hotel search tool found in allowlist. Discovered: "
                    + ", ".join(getattr(t, "name", "?") for t in tools)
                )

            search_tool = matching_tools[0]
            args = {"query": search_query}
            if hasattr(search_tool, "args_schema") and search_tool.args_schema:
                schema_fields = getattr(
                    search_tool.args_schema, "model_fields", {}
                ) or getattr(search_tool.args_schema, "__fields__", {})
                if "q" in schema_fields:
                    args = {"q": search_query}
                elif "keywords" in schema_fields:
                    args = {"keywords": search_query}
                elif "search_query" in schema_fields:
                    args = {"search_query": search_query}

            raw_res = await search_tool.ainvoke(args)
            normalized = self._normalize_mcp_output(raw_res)
            if not normalized or not normalized.strip():
                raise RuntimeError("DuckDuckGo MCP tool returned empty output")
            return normalized.strip()

    def _normalize_mcp_output(self, output: Any) -> str:
        """Normalizes list, content-block, dict, or string output from MCP tools into clean text snippets with newlines."""
        if not output:
            return ""
        if isinstance(output, str):
            return output.strip()
        if isinstance(output, list):
            snippets = []
            for item in output:
                if isinstance(item, str):
                    if item.strip():
                        snippets.append(f"- {item.strip()}")
                elif isinstance(item, dict):
                    title = (
                        item.get("title")
                        or item.get("name")
                        or item.get("heading")
                        or ""
                    )
                    content = (
                        item.get("content")
                        or item.get("snippet")
                        or item.get("text")
                        or item.get("description")
                        or str(item)
                    )
                    if title and content and title != content:
                        snippets.append(f"- {title}: {content}")
                    else:
                        snippets.append(f"- {content}")
                elif hasattr(item, "text"):
                    text_val = getattr(item, "text", "")
                    if text_val:
                        snippets.append(f"- {text_val}")
                else:
                    snippets.append(f"- {item!s}")
            return "\n".join(snippets).strip()
        if isinstance(output, dict):
            results = (
                output.get("results")
                or output.get("data")
                or output.get("content")
                or output.get("output")
            )
            if results and results != output:
                return self._normalize_mcp_output(results)
            return json.dumps(output)
        return str(output).strip()

    def _fallback_hotels(self, location: str) -> ProviderResult:
        """Tertiary fallback accommodation recommendations when live services are unavailable."""
        text = (
            f"Hotel Information for '{location}':\n"
            f"- Status: Live accommodation data unavailable (degraded fallback).\n"
            f"- Recommended Hotel Ranges in {location}:\n"
            f"  1. Luxury: 5-Star City Center Grand Hotel ($300 - $550/night) - Full amenities, spa, central location.\n"
            f"  2. Boutique / Mid-Range: Modern Historic District Hotel ($140 - $220/night) - High walkability, breakfast included.\n"
            f"  3. Value: Metro-adjacent Boutique Pod/Aparthotel ($60 - $110/night) - Clean, fast Wi-Fi, transit access."
        )
        return ProviderResult(text=text, source="fallback", degraded=True)
