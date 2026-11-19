"""Weather Agent Service REST and Health Check API."""

from typing import Annotated

from fastapi import Depends, FastAPI

from services.common.auth_middleware import AuthenticatedUser, get_current_user
from services.weather_service.provider import WeatherProvider

app = FastAPI(title="Weather Agent Service", version="2.0.0")
provider = WeatherProvider()

CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "weather-agent-service"}


@app.get("/health/ready")
async def readiness():
    r = await provider.get_redis()
    await r.ping()
    return {"status": "READY", "redis": "connected"}


@app.get("/api/v1/weather/get")
async def get_weather(query: str, user: CurrentUser):
    """Authenticated direct REST query for weather data."""
    return await provider.get_weather(query)
