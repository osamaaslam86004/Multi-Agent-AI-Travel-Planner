"""
Itinerary and Synthesis LLM Engine with Resilient Multi-Provider Fallback Chain
(Groq -> Google Gemini -> Local Hugging Face <12GB VRAM).
"""

import logging
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from services.common.llm_provider import LLMResult
from services.common.resilient_chain import ResilientLLMChain

logger = logging.getLogger("travelbrain.synthesis_engine")


class SynthesisEngine:
    """
    Orchestrates LLM prompts for multi-agent synthesis and final itinerary formatting
    via a 3-tier resilient fallback chain (Groq -> Gemini -> Local HuggingFace).
    """

    def __init__(
        self,
        chain: ResilientLLMChain | None = None,
        model_name: str | None = None,
    ):
        self.chain = chain or ResilientLLMChain()
        self.model_name = model_name or "resilient-multi-provider-chain"
        self.last_result: LLMResult | None = None

    async def generate_itinerary(
        self,
        user_query: str,
        flight_results: str,
        hotel_results: str,
        weather_results: str,
        temperature: float = 0.3,
    ) -> str:
        """
        Synthesizes agent outputs into a structured day-by-day travel itinerary
        using the resilient multi-provider fallback chain.
        """
        system_prompt = (
            "You are an expert travel planner. Synthesize flight options, hotels, "
            "and weather data into a realistic, structured, day-by-day itinerary. "
            "CRITICAL INSTRUCTION: If any upstream domain (flights, hotels, or weather) is marked "
            "as degraded, missing, or unavailable, explicitly state 'data unavailable' or 'information unavailable' "
            "for that specific domain rather than inventing, hallucinating, or fabricating numbers, prices, weather conditions, or facts."
        )
        user_prompt = (
            f"User Query: {user_query}\n\n"
            f"Flight Information:\n{flight_results}\n\n"
            f"Hotel Recommendations:\n{hotel_results}\n\n"
            f"Weather Outlook:\n{weather_results}\n\n"
            f"Provide a structured itinerary highlighting activities, meals, and logistics."
        )
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        try:
            result = await self.chain.generate(messages, temperature=temperature)
            self.last_result = result
            logger.info(
                f"Itinerary generated via provider: {result.provider_name} "
                f"({result.model_name}) in {result.latency_ms:.1f}ms"
            )
            return result.content
        except Exception as exc:
            logger.error(
                f"Resilient LLM chain failed to generate itinerary: {exc}. Using deterministic safety fallback."
            )
            return self._heuristic_itinerary(
                user_query, flight_results, hotel_results, weather_results
            )

    async def format_final_response(
        self,
        user_query: str,
        flight_results: str,
        hotel_results: str,
        weather_results: str,
        itinerary: str,
        temperature: float = 0.2,
    ) -> str:
        """
        Formats the final customer-ready Markdown presentation
        using the resilient multi-provider fallback chain.
        """
        system_prompt = (
            "You are TravelBrain AI, a premier executive travel assistant. Format the final "
            "travel plan with executive summaries, clear markdown tables, budget breakdowns, "
            "and actionable tips. "
            "CRITICAL INSTRUCTION: If any upstream domain (flights, hotels, or weather) is marked "
            "as degraded, missing, or unavailable, explicitly state 'data unavailable' or 'information unavailable' "
            "for that specific domain rather than inventing, hallucinating, or fabricating numbers, prices, weather conditions, or facts."
        )
        user_prompt = (
            f"Trip Request: {user_query}\n\n"
            f"Flights:\n{flight_results}\n\n"
            f"Hotels:\n{hotel_results}\n\n"
            f"Weather:\n{weather_results}\n\n"
            f"Itinerary Draft:\n{itinerary}\n\n"
            f"Deliver the final executive trip dossier."
        )
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        try:
            result = await self.chain.generate(messages, temperature=temperature)
            self.last_result = result
            logger.info(
                f"Final response formatted via provider: {result.provider_name} "
                f"({result.model_name}) in {result.latency_ms:.1f}ms"
            )
            return result.content
        except Exception as exc:
            logger.error(
                f"Resilient LLM chain failed to format final response: {exc}. Using deterministic safety fallback."
            )
            return self._heuristic_final_response(
                user_query, flight_results, hotel_results, weather_results, itinerary
            )

    async def generate_structured_plan(
        self,
        user_query: str,
        response_schema: dict[str, Any],
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        """
        Generates structured JSON plan conforming to schema using provider-level JSON enforcement.
        """
        messages = [
            SystemMessage(content="You are an enterprise travel planner."),
            HumanMessage(content=f"Create a structured plan for: {user_query}"),
        ]
        result = await self.chain.generate_structured(
            messages=messages,
            response_format=response_schema,
            temperature=temperature,
        )
        self.last_result = result
        return result.structured_data or {}

    def _heuristic_itinerary(
        self, query: str, flights: str, hotels: str, weather: str
    ) -> str:
        return (
            f"### Proposed Itinerary for '{query}'\n\n"
            f"**Day 1: Arrival, Check-in & Orientation**\n"
            f"- Settle in after transit; explore immediate neighborhood.\n\n"
            f"**Day 2: Cultural Landmarks & Core Highlights**\n"
            f"- Morning tour of premier historical and cultural sites.\n"
            f"- Afternoon culinary immersion.\n\n"
            f"**Day 3: Nature, Scenery & Scenic Exploration**\n"
            f"- Full-day excursion optimized for local conditions.\n\n"
            f"**Day 4: Leisure, Souvenirs & Departure**\n"
            f"- Relaxed morning cafe visit and transit to airport."
        )

    def _heuristic_final_response(
        self, query: str, flights: str, hotels: str, weather: str, itinerary: str
    ) -> str:
        return (
            f"# 🌍 Your Executive Travel Plan\n\n"
            f"**Target Request**: {query}\n\n"
            f"---\n\n"
            f"## ✈️ Flight Intelligence\n{flights}\n\n"
            f"## 🏨 Recommended Accommodations\n{hotels}\n\n"
            f"## ☀️ Weather Outlook\n{weather}\n\n"
            f"---\n\n"
            f"## 📅 Curated Itinerary\n{itinerary}\n\n"
            f"---\n\n"
            f"💡 **TravelBrain Advisory**: Live status indicated above. Safe travels!"
        )
