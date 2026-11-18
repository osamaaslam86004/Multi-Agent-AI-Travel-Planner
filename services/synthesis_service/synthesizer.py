"""
Itinerary and Synthesis LLM Engine with Groq Integration and Fallbacks.
"""

import logging
import os

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_groq import ChatGroq

logger = logging.getLogger("travelbrain.synthesis_engine")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")


class SynthesisEngine:
    """Orchestrates LLM prompts for multi-agent synthesis and final itinerary formatting."""

    def __init__(self, model_name: str = "llama-3.3-70b-versatile"):
        self.model_name = model_name
        self._llm: ChatGroq | None = None

    def get_llm(self) -> ChatGroq | None:
        if not self._llm and GROQ_API_KEY:
            self._llm = ChatGroq(
                groq_api_key=GROQ_API_KEY,
                model_name=self.model_name,
                temperature=0.3,
            )
        return self._llm

    async def generate_itinerary(
        self,
        user_query: str,
        flight_results: str,
        hotel_results: str,
        weather_results: str,
    ) -> str:
        """Synthesizes agent outputs into a cohesive day-by-day travel itinerary."""
        llm = self.get_llm()
        if not llm:
            return self._heuristic_itinerary(
                user_query, flight_results, hotel_results, weather_results
            )

        system_prompt = (
            "You are an expert travel planner. Synthesize flight options, hotels, "
            "and weather data into a realistic, structured, day-by-day itinerary."
        )
        user_prompt = (
            f"User Query: {user_query}\n\n"
            f"Flight Information:\n{flight_results}\n\n"
            f"Hotel Recommendations:\n{hotel_results}\n\n"
            f"Weather Outlook:\n{weather_results}\n\n"
            f"Provide a structured itinerary highlighting activities, meals, and logistics."
        )
        try:
            response = await llm.ainvoke(
                [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=user_prompt),
                ]
            )
            return response.content
        except Exception as exc:
            logger.error(f"Groq itinerary generation error: {exc}. Using fallback.")
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
    ) -> str:
        """Formats the final customer-ready Markdown presentation."""
        llm = self.get_llm()
        if not llm:
            return self._heuristic_final_response(
                user_query, flight_results, hotel_results, weather_results, itinerary
            )

        system_prompt = (
            "You are TravelBrain AI, a premier executive travel assistant. Format the final "
            "travel plan with executive summaries, clear markdown tables, budget breakdowns, "
            "and actionable tips."
        )
        user_prompt = (
            f"Trip Request: {user_query}\n\n"
            f"Flights:\n{flight_results}\n\n"
            f"Hotels:\n{hotel_results}\n\n"
            f"Weather:\n{weather_results}\n\n"
            f"Itinerary Draft:\n{itinerary}\n\n"
            f"Deliver the final executive trip dossier."
        )
        try:
            response = await llm.ainvoke(
                [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=user_prompt),
                ]
            )
            return response.content
        except Exception as exc:
            logger.error(f"Groq final synthesis error: {exc}. Using fallback.")
            return self._heuristic_final_response(
                user_query, flight_results, hotel_results, weather_results, itinerary
            )

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
            f"- Full-day excursion optimized for current weather conditions.\n\n"
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
            f"💡 **TravelBrain Advisory**: All estimates are updated in real-time. Safe travels!"
        )
