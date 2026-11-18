"""
Hotel Provider with 3-Tier Fallback Architecture:
Tier 1: Tavily Search API (Primary)
Tier 2: DuckDuckGo MCP Server via stdio (Secondary)
Tier 3: Static Accommodation Heuristics (Tertiary Guaranteed Fallback)
"""

import hashlib
import json
import logging
import os
from typing import Any

import redis.asyncio as aioredis
from langchain_mcp_adapters.client import MultiServerMCPClient
from tavily import TavilyClient

from services.common.resilience import CircuitBreaker

logger = logging.getLogger("travelbrain.hotel_service")

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/2")

# Independent Circuit Breakers for Tier 1 and Tier 2
tavily_breaker = CircuitBreaker("TavilyHotelBreaker", fail_max=3, reset_timeout=30.0)
mcp_breaker = CircuitBreaker("DuckDuckGoMCPBreaker", fail_max=3, reset_timeout=20.0)


class HotelProvider:
    """Manages accommodation searches via a 3-Tier Enterprise Fallback Architecture."""

    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._redis: aioredis.Redis | None = None
        self.tavily_breaker = tavily_breaker
        self.mcp_breaker = mcp_breaker

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis

    def _cache_key(self, query: str) -> str:
        h = hashlib.sha256(query.strip().lower().encode()).hexdigest()[:16]
        return f"hotel:cache:{h}"

    async def search_hotels(self, query: str) -> dict[str, Any]:
        """High-level hotel search with 12-hour Redis caching and 3-Tier failover execution."""

        r = await self.get_redis()
        cache_key = self._cache_key(query)
        cached_data = await r.get(cache_key)

        if cached_data:
            logger.info(f"Hotel cache hit for query: '{query}'")
            return {"results": json.loads(cached_data), "cached": True}

        results = await self._execute_tiered_search(query)

        # Store in Redis Cache (12-hour / 43200-second TTL)
        await r.setex(cache_key, 43200, json.dumps(results))
        return {"results": results, "cached": False}

    async def _execute_tiered_search(self, query: str) -> str:
        """Orchestrates sequential failover across Tier 1 (Tavily), Tier 2 (DuckDuckGo MCP), and Tier 3 (Static Heuristics)."""
        # Tier 1 — Primary Provider (Tavily API)
        try:
            logger.info(
                f"Attempting Tier 1 (Tavily API) hotel search for query: '{query}'"
            )
            return await self.tavily_breaker.call(self._fetch_tavily_hotels, query)
        except Exception as exc:
            logger.warning(
                f"Tier 1 (Tavily API) failed or circuit OPEN for query '{query}': {exc}. Failing over to Tier 2 (DuckDuckGo MCP)..."
            )

        # Tier 2 — Secondary Fallback (DuckDuckGo MCP Server)
        try:
            logger.info(
                f"Attempting Tier 2 (DuckDuckGo MCP Server) hotel search for query: '{query}'"
            )
            return await self.mcp_breaker.call(self._fetch_duckduckgo_mcp, query)
        except Exception as exc:
            logger.warning(
                f"Tier 2 (DuckDuckGo MCP) failed or circuit OPEN for query '{query}': {exc}. Failing over to Tier 3 (Static Heuristics)..."
            )

        # Tier 3 — Tertiary Guaranteed Fallback (Static Heuristics)
        logger.info(
            f"Executing Tier 3 (Static Heuristic Fallback) for query: '{query}'"
        )
        return await self._fallback_hotels(query)

    async def _fetch_tavily_hotels(self, query: str) -> str:
        """Call Tavily search API for curated hotel recommendations."""
        if not TAVILY_API_KEY:
            raise ValueError("Tavily API key not configured")
        client = TavilyClient(api_key=TAVILY_API_KEY)
        response = client.search(
            query=f"Best recommended hotels accommodations in {query}",
            search_depth="advanced",
            max_results=5,
        )
        snippets = [
            f"- {item.get('title')}: {item.get('content')}"
            for item in response.get("results", [])
            if item.get("title") or item.get("content")
        ]
        res_text = "".join(snippets).strip()
        if not res_text:
            raise RuntimeError("Tavily API returned empty hotel results")
        return res_text

    async def _fetch_duckduckgo_mcp(self, query: str) -> str:
        """Secondary fallback: Connect to DuckDuckGo MCP Server via stdio and execute search."""

        server_config = {
            "duckduckgo": {
                "command": "uvx",
                "args": ["duckduckgo-mcp"],
                "transport": "stdio",
            }
        }

        async with MultiServerMCPClient(server_config) as client:
            tools = client.get_tools()

            if not tools:
                raise RuntimeError("No tools discovered from DuckDuckGo MCP server")

            search_tool = None
            for t in tools:
                tool_name = getattr(t, "name", "").lower()
                if "search" in tool_name or "ddg" in tool_name or "duck" in tool_name:
                    search_tool = t
                    break

            if not search_tool:
                search_tool = tools[0]

            search_query = f"Best recommended hotels accommodations in {query}"

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
        """Normalizes list, content-block, dict, or string output from MCP tools into clean text snippets."""

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
            return "".join(snippets).strip()

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

    async def _fallback_hotels(self, query: str) -> str:
        """Tertiary fallback accommodation recommendations when Tavily and DuckDuckGo MCP are unavailable."""
        return (
            f"Hotel Recommendations for '{query}':"
            f"1. Luxury: 5-Star City Center Grand Hotel (00 - 50/night) - Full amenities, spa, central location."
            f"2. Boutique / Mid-Range: Modern Historic District Hotel (40 - 20/night) - High walkability, breakfast included."
            f"3. Value: Metro-adjacent Boutique Pod/Aparthotel (0 - 10/night) - Clean, fast Wi-Fi, transit access."
        )
