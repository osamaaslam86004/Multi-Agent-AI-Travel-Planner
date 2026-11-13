"""Centralized registry for managing agent prompt templates and configuration."""

from typing import Any


class PromptRegistry:
    """Centralized registry housing all agent system and user prompt templates."""

    def __init__(self) -> None:
        self._prompts: dict[str, str] = {
            "flight_system": "You are an expert travel flight planner.",
            "flight_user": """You are a travel flight expert.
User Query:
{query}
Airport Information:
{airport_data}
Airline Information:
{airline_data}
Generate:
1. Likely departure airport
2. Likely arrival airport
3. Airlines serving this route
4. Typical flight duration
5. Estimated airfare range
6. Peak season pricing warning
7. Booking advice
Return concise travel guidance.""",
            "hotel_search_query": "Best hotels for {user_query}",
            "destination_extraction": """Extract only the destination city or country.
Query:
{query}
Return only destination name.""",
            "weather_results_template": """Current Weather:
{weather_data}
Forecast:
{forecast_data}""",
            "itinerary_system": "You are an expert travel planner.",
            "itinerary_user": """Create a complete travel itinerary.
User Query:
{user_query}
Flight Results:
{flight_results}
Hotel Results:
{hotel_results}
Weather Results:
{weather_results}
Make the itinerary practical, budget-aware, and easy to follow.""",
            "final_system": "You are a professional AI travel booking assistant.",
            "final_user": """Generate the final travel response for the user.
User Request:
{user_query}
Flights:
{flight_results}
Hotels:
{hotel_results}
Weather:
{weather_results}
Itinerary:
{itinerary}
Format the final answer beautifully using these sections:
1. Trip Summary
2. Flight Information
3. Hotel Suggestions
4. Weather Information
5. Day-by-Day Itinerary
6. Estimated Budget
7. Final Recommendations
Important:
- Be clear and practical.
- Mention that live flight API may not provide ticket prices if pricing is unavailable.
- Include weather-based travel advice.
- Keep the response useful for real travel planning.""",
        }

    def register_prompt(self, name: str, template: str) -> None:
        """Register or override a prompt template."""
        self._prompts[name] = template

    def get_prompt(self, name: str) -> str:
        """Retrieve a raw prompt template by name."""
        if name not in self._prompts:
            raise KeyError(f"Prompt '{name}' not found in registry.")
        return self._prompts[name]

    def format_prompt(self, name: str, **kwargs: Any) -> str:
        """Retrieve and format a prompt template with provided variables."""
        template = self.get_prompt(name)
        return template.format(**kwargs)


# Singleton prompt registry instance
default_prompt_registry = PromptRegistry()
