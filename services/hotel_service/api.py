"""Hotel Agent Service REST and Health Check API."""

from typing import Annotated

from fastapi import Depends, FastAPI

from services.common.auth_middleware import AuthenticatedUser, get_current_user
from services.hotel_service.provider import HotelProvider

app = FastAPI(title="Hotel Agent Service", version="2.0.0")
provider = HotelProvider()

CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "hotel-agent-service"}


@app.get("/health/ready")
async def readiness():
    r = await provider.get_redis()
    await r.ping()
    return {"status": "READY", "redis": "connected"}


@app.get("/api/v1/hotels/search")
async def search(query: str, user: CurrentUser):
    """Authenticated direct REST query for hotel data."""
    return await provider.search_hotels(query)
