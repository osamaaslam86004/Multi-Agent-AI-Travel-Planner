"""Flight Agent Service REST and Health Check API."""

from fastapi import Depends, FastAPI

from services.common.auth_middleware import AuthenticatedUser, get_current_user
from services.flight_service.provider import FlightProvider

app = FastAPI(title="Flight Agent Service", version="2.0.0")
provider = FlightProvider()


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "flight-agent-service"}


@app.get("/health/ready")
async def readiness():
    r = await provider.get_redis()
    await r.ping()
    return {"status": "READY", "redis": "connected"}


@app.get("/api/v1/flights/search")
async def search(query: str, user: AuthenticatedUser = Depends(get_current_user)):
    """Authenticated direct REST query for flight data."""
    return await provider.search_flights(query)
