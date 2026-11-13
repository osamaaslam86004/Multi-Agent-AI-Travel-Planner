"""Backward-compatible prompt exports re-exporting from prompts_registry."""

from src.agents.prompts_registry import default_prompt_registry

FLIGHT_SYSTEM_PROMPT = default_prompt_registry.get_prompt("flight_system")
FLIGHT_AGENT_PROMPT = default_prompt_registry.get_prompt("flight_user")
HOTEL_SEARCH_QUERY = default_prompt_registry.get_prompt("hotel_search_query")
DESTINATION_EXTRACTION_PROMPT = default_prompt_registry.get_prompt(
    "destination_extraction"
)
WEATHER_RESULTS_TEMPLATE = default_prompt_registry.get_prompt(
    "weather_results_template"
)
ITINERARY_SYSTEM_PROMPT = default_prompt_registry.get_prompt("itinerary_system")
ITINERARY_AGENT_PROMPT = default_prompt_registry.get_prompt("itinerary_user")
FINAL_SYSTEM_PROMPT = default_prompt_registry.get_prompt("final_system")
FINAL_AGENT_PROMPT = default_prompt_registry.get_prompt("final_user")
