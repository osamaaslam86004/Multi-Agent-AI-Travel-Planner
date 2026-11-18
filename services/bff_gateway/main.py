"""
API Gateway / Backend For Frontend (BFF) Service.
Handles rate limiting, secure HTTP-only cookies, anti-CSRF, and SSE trip streaming.
"""

import asyncio
import json
import logging
import os
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from services.bff_gateway.session_manager import (
    SESSION_COOKIE_NAME,
    SessionManager,
)
from services.common.event_bus import EventBus
from services.common.schemas import CloudEvent, PlanningInitiatedPayload
from services.common.telemetry import extract_traceparent

logger = logging.getLogger("travelbrain.gateway")

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

app = FastAPI(
    title="TravelBrain API Gateway & BFF",
    version="2.0.0",
    description="Edge Gateway, Authentication Barrier, and Server-Sent Events Streaming",
)

session_manager = SessionManager(redis_url=REDIS_URL)
event_bus = EventBus(redis_url=REDIS_URL)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

if FRONTEND_DIR.exists():
    app.mount(
        "/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static"
    )
    templates = Jinja2Templates(directory=str(FRONTEND_DIR / "templates"))
else:
    templates = None


class TripPlanRequest(BaseModel):
    message: str
    destination: str | None = None
    departure_city: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str | None = None


@app.on_event("startup")
async def startup_event():
    await event_bus.connect()
    logger.info("BFF Gateway initialized and connected to Redis Event Bus.")


@app.on_event("shutdown")
async def shutdown_event():
    await event_bus.close()


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "bff-gateway"}


@app.get("/health/ready")
async def readiness():
    try:
        r = await session_manager.get_redis()
        await r.ping()
        return {"status": "READY", "redis": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")


# Frontend UI Route
@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    if templates and (FRONTEND_DIR / "templates" / "index.html").exists():
        return templates.TemplateResponse("index.html", {"request": request})
    return HTMLResponse("<h1>TravelBrain AI Microservices Gateway Active</h1>")


# ---------------------------------------------------------------------------
# Authentication & Session Handshake
# ---------------------------------------------------------------------------
@app.post("/api/v1/auth/login")
async def login(req: LoginRequest, response: Response):
    """
    Exchanges user credentials with Auth Service, creates secure session,
    and returns HTTP-only cookie with Anti-CSRF token in header.
    """
    async with httpx.AsyncClient() as client:
        auth_resp = await client.post(
            f"{AUTH_SERVICE_URL}/api/v1/auth/login",
            json={"email": req.email, "password": req.password},
            timeout=5.0,
        )
        if auth_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed with Auth Service",
            )
        token_data = auth_resp.json()

    jwt_token = token_data["access_token"]
    user_id = token_data["user_id"]
    email = token_data["email"]

    # Store JWT in server-side Redis session
    session_id, csrf_token = await session_manager.create_session(
        jwt_token=jwt_token, user_id=user_id, email=email
    )

    # Set secure HTTP-only cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=os.getenv("ENVIRONMENT") == "production",
        samesite="lax",
        max_age=86400,
    )
    # Expose Anti-CSRF token header
    response.headers["X-CSRF-Token"] = csrf_token
    return {
        "status": "authenticated",
        "user_id": user_id,
        "email": email,
        "csrf_token": csrf_token,
    }


@app.post("/api/v1/auth/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        await session_manager.destroy_session(session_id)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"status": "logged_out"}


@app.get("/api/v1/auth/me")
async def get_me(request: Request):
    """Returns profile and active CSRF token for the current session."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        # Fallback to anonymous guest session for immediate demonstration
        guest_email = "guest@travelbrain.ai"
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{AUTH_SERVICE_URL}/api/v1/auth/login",
                json={"email": guest_email},
                timeout=5.0,
            )
            token_data = resp.json()
        guest_sess_id, guest_csrf = await session_manager.create_session(
            jwt_token=token_data["access_token"],
            user_id=token_data["user_id"],
            email=guest_email,
        )
        json_resp = JSONResponse(
            {
                "user_id": token_data["user_id"],
                "email": guest_email,
                "csrf_token": guest_csrf,
                "guest": True,
            }
        )
        json_resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=guest_sess_id,
            httponly=True,
            samesite="lax",
            max_age=86400,
        )
        json_resp.headers["X-CSRF-Token"] = guest_csrf
        return json_resp

    session_data = await session_manager.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="Session expired")

    return {
        "user_id": session_data.get("user_id"),
        "email": session_data.get("email"),
        "csrf_token": session_data.get("csrf_token"),
    }


# ---------------------------------------------------------------------------
# Trip Planning Orchestration & SSE Real-time Streaming
# ---------------------------------------------------------------------------
@app.post("/api/v1/trips/plan")
async def plan_trip(req: TripPlanRequest, request: Request):
    """
    Submits a new travel query.
    Enforces rate-limits, attaches W3C traceparent, and publishes
    a CloudEvent to initiate the asynchronous Scatter-Gather workflow.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not await session_manager.check_rate_limit(
        client_ip, max_requests=30, window_seconds=60
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait a moment before trying again.",
        )

    # Resolve session
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    user_id = "guest_user"
    if session_id:
        sess = await session_manager.get_session(session_id)
        if sess:
            user_id = sess.get("user_id", user_id)

    correlation_id = f"trip_{uuid.uuid4().hex[:12]}"
    traceparent = extract_traceparent(dict(request.headers))

    # Construct CloudEvent
    event = CloudEvent[PlanningInitiatedPayload](
        source="/services/bff-gateway",
        type="com.travelbrain.planning.initiated",
        traceparent=traceparent,
        data=PlanningInitiatedPayload(
            correlation_id=correlation_id,
            user_id=user_id,
            user_query=req.message,
            destination=req.destination,
            departure_city=req.departure_city,
        ),
    )

    # Publish to Redis Stream for concurrent agent workers
    await event_bus.publish("stream:travel:planning:initiated", event)

    return {
        "correlation_id": correlation_id,
        "status": "initiated",
        "stream_url": f"/api/v1/trips/{correlation_id}/stream",
        "traceparent": traceparent,
    }


@app.get("/api/v1/trips/{correlation_id}/stream")
async def stream_trip_progress(correlation_id: str):
    """
    Server-Sent Events (SSE) endpoint providing real-time progress updates
    and final synthesized itinerary to the client.
    """
    channel_name = f"trip:stream:{correlation_id}"

    async def sse_generator() -> AsyncGenerator[str, None]:
        r = await session_manager.get_redis()
        pubsub = r.pubsub()
        await pubsub.subscribe(channel_name)
        yield f"data: {json.dumps({'stage': 'initiated', 'message': 'Trip planning request accepted by gateway.'})}\n\n"

        timeout_seconds = 120
        start_time = asyncio.get_event_loop().time()

        try:
            while True:
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed > timeout_seconds:
                    yield f"data: {json.dumps({'stage': 'timeout', 'error': 'Trip synthesis timed out.'})}\n\n"
                    break

                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if message and message.get("type") == "message":
                    payload = message.get("data")
                    yield f"data: {payload}\n\n"

                    # Check if final payload is delivered
                    try:
                        parsed = json.loads(payload)
                        if parsed.get("stage") in ["completed", "error"]:
                            break
                    except Exception:
                        pass
                await asyncio.sleep(0.05)
        finally:
            await pubsub.unsubscribe(channel_name)
            await pubsub.close()

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
