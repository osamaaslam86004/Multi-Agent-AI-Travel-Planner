"""
API Gateway / Backend For Frontend (BFF) Service.
Handles rate limiting per user/tenant, secure HTTP-only cookie sessions with rotation,
anti-CSRF enforcement, Idempotency-Key verification, trip ownership, and SSE streaming.
"""

import asyncio
import json
import logging
import os
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from services.bff_gateway.session_manager import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    SessionManager,
)
from services.common.db import (
    get_trip_by_id,
    relay_outbox,
    write_outbox,
)
from services.common.event_bus import EventBus
from services.common.pii_redactor import redact_pii
from services.common.schemas import CloudEvent, PlanningInitiatedPayload
from services.common.telemetry import extract_traceparent

logger = logging.getLogger("travelbrain.gateway")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
app = FastAPI(
    title="TravelBrain API Gateway & BFF",
    version="2.0.0",
    description="Edge Gateway, Multi-Tenant Session Barrier, and Authenticated SSE Streaming",
)
session_manager = SessionManager(redis_url=REDIS_URL, password=REDIS_PASSWORD)
event_bus = EventBus(redis_url=REDIS_URL, password=REDIS_PASSWORD)
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
    message: str = Field(
        ..., max_length=2000, description="User query bounded to max 2000 characters"
    )
    destination: str | None = Field(None, max_length=200)
    departure_city: str | None = Field(None, max_length=200)
    start_date: str | None = Field(None, max_length=50)
    end_date: str | None = Field(None, max_length=50)
    dates: str | None = Field(None, max_length=100)


class LoginRequest(BaseModel):
    email: str
    password: str | None = None
    tenant_id: str = "default"


@app.on_event("startup")
async def startup_event():
    try:
        await event_bus.connect()
        logger.info("BFF Gateway initialized and connected to Redis Event Bus.")
        asyncio.create_task(periodic_outbox_relay())
    except (OSError, RuntimeError, ValueError) as exc:
        logger.warning("BFF Gateway startup event bus connect fallback: %s", exc)


async def periodic_outbox_relay():
    while True:
        try:
            await relay_outbox(event_bus)
        except (
            OSError,
            RuntimeError,
            TimeoutError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            logger.debug("Outbox relay error: %s", exc)
        await asyncio.sleep(1.0)


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
        if r:
            await r.ping()
        return {"status": "READY", "redis": "connected" if r else "dummy"}
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")


@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    if templates and (FRONTEND_DIR / "templates" / "index.html").exists():
        return templates.TemplateResponse("index.html", {"request": request})
    return HTMLResponse("<h1>TravelBrain AI Microservices Gateway Active</h1>")


@app.post("/api/v1/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    if not await session_manager.check_rate_limit(
        client_ip, tenant_id=req.tenant_id, max_requests=10, window_seconds=60
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait a minute.",
        )
    async with httpx.AsyncClient() as client:
        auth_resp = await client.post(
            f"{AUTH_SERVICE_URL}/api/v1/auth/login",
            json={
                "email": req.email,
                "password": req.password,
                "tenant_id": req.tenant_id,
            },
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
    tenant_id = token_data.get("tenant_id", req.tenant_id)
    roles = token_data.get("roles", ["traveler"])
    old_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    session_id, csrf_token = await session_manager.create_session(
        jwt_token=jwt_token,
        user_id=user_id,
        email=email,
        tenant_id=tenant_id,
        roles=roles,
        old_session_id=old_session_id,
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=os.getenv("ENVIRONMENT") == "production",
        samesite="lax",
        path="/",
        max_age=86400,
    )
    response.headers[CSRF_HEADER_NAME] = csrf_token
    return {
        "status": "authenticated",
        "user_id": user_id,
        "email": email,
        "tenant_id": tenant_id,
        "csrf_token": csrf_token,
    }


@app.post("/api/v1/auth/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        sess = await session_manager.get_session(session_id)
        tenant_id = sess.get("tenant_id", "default") if sess else "default"
        await session_manager.destroy_session(session_id, tenant_id=tenant_id)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@app.get("/api/v1/auth/me")
async def get_me(request: Request):
    """
    Returns active user profile from session. Requires authentication;
    no unauthenticated guest session minting or auth-service call amplification.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthenticated. Missing session cookie.",
        )
    session_data = await session_manager.get_session(session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )
    return {
        "user_id": session_data.get("user_id"),
        "email": session_data.get("email"),
        "tenant_id": session_data.get("tenant_id", "default"),
        "csrf_token": session_data.get("csrf_token"),
    }


@app.post("/api/v1/trips/plan")
async def plan_trip(req: TripPlanRequest, request: Request, response: Response):
    """
    Enforces authentication, Anti-CSRF header verification, input bounds,
    rate limiting per user/tenant, Idempotency-Key caching, full-UUID IDs, and trip ownership.
    """
    session_data = await session_manager.validate_request(request)
    user_id = session_data["user_id"]
    tenant_id = session_data.get("tenant_id", "default")
    client_ip = request.client.host if request.client else "unknown"
    rate_limit_target = f"{tenant_id}:{user_id}:{client_ip}"
    if not await session_manager.check_rate_limit(
        rate_limit_target, tenant_id=tenant_id, max_requests=30, window_seconds=60
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait a moment before trying again.",
        )
    # Idempotency-Key Check
    idempotency_key = request.headers.get("Idempotency-Key") or request.headers.get(
        "x-idempotency-key"
    )
    r = await session_manager.get_redis()
    if idempotency_key and r:
        idem_redis_key = f"idempotency:{tenant_id}:{user_id}:{idempotency_key}"
        cached_resp = await r.get(idem_redis_key)
        if cached_resp:
            logger.info(
                "Idempotency key hit for user %s (%s)", user_id, idempotency_key
            )
            return JSONResponse(content=json.loads(cached_resp))
    # Full 128-bit UUID for collision resistance and trip ownership
    correlation_id = f"trip_{uuid.uuid4().hex}"
    # Bind trip ownership in Redis
    if r:
        await r.setex(f"trip:ownership:{tenant_id}:{correlation_id}", 86400, user_id)
    clean_message = redact_pii(req.message)
    traceparent = extract_traceparent(dict(request.headers))
    payload_data = PlanningInitiatedPayload(
        correlation_id=correlation_id,
        user_id=user_id,
        tenant_id=tenant_id,
        user_query=clean_message,
        destination=req.destination,
        departure_city=req.departure_city,
        start_date=req.start_date,
        end_date=req.end_date,
        dates=req.dates,
    )

    event = CloudEvent[PlanningInitiatedPayload](
        source="/services/bff-gateway",
        type="com.travelbrain.planning.initiated.v1",
        subject=correlation_id,
        traceparent=traceparent,
        data=payload_data,
    )

    # Write trip record and event to transactional Outbox in Postgres
    await write_outbox(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        stream_name="stream:travel:planning:initiated",
        event_type="com.travelbrain.planning.initiated.v1",
        payload=payload_data.model_dump(),
    )

    # Publish directly for immediate dispatch
    await event_bus.publish("stream:travel:planning:initiated", event)
    plan_response = {
        "correlation_id": correlation_id,
        "status": "initiated",
        "stream_url": f"/api/v1/trips/{correlation_id}/stream",
        "tenant_id": tenant_id,
        "traceparent": traceparent,
    }
    # Cache response under Idempotency-Key if provided
    if idempotency_key and r:
        idem_redis_key = f"idempotency:{tenant_id}:{user_id}:{idempotency_key}"
        await r.setex(idem_redis_key, 3600, json.dumps(plan_response))
    return plan_response


@app.get("/api/v1/trips/{correlation_id}/stream")
async def stream_trip_progress(
    correlation_id: str,
    request: Request,
    last_event_id: str | None = None,
):
    """
    Authenticated Server-Sent Events (SSE) trip progress stream reading from per-trip Redis Stream (trip:events:{id}).
    Supports snapshot on connect, Last-Event-ID replay, id: field tagging, keepalives, and ownership verification.
    """
    session_data = await session_manager.validate_request(request)
    user_id = session_data["user_id"]
    tenant_id = session_data.get("tenant_id", "default")
    r = await session_manager.get_redis()

    if r:
        trip_owner = await r.get(f"trip:ownership:{tenant_id}:{correlation_id}")
        if trip_owner and trip_owner != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Trip belongs to another user.",
            )

    header_last_id = request.headers.get("Last-Event-ID") or last_event_id or "0-0"
    stream_name = f"trip:events:{correlation_id}"

    async def sse_generator() -> AsyncGenerator[str, None]:
        if not r:
            yield f"id: 0-0\ndata: {json.dumps({'stage': 'initiated', 'message': 'Gateway in offline mode.'})}\n\n"
            return

        last_delivered_id = header_last_id if header_last_id != "0-0" else "0-0"

        # Step 1: Replay existing stream events from last_delivered_id (Snapshot on connect)
        try:
            range_events = await r.xrange(stream_name, min=last_delivered_id, max="+")
            for msg_id, data in range_events:
                if msg_id == header_last_id and header_last_id != "0-0":
                    continue
                payload_str = data.get("data", "{}")
                yield f"id: {msg_id}\ndata: {payload_str}\n\n"
                last_delivered_id = msg_id
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            logger.debug("Error replaying stream events: %s", exc)

        # Step 2: Live stream reading with periodic keepalives
        keepalive_counter = 0
        while True:
            try:
                entries = await r.xread(
                    {stream_name: last_delivered_id}, count=10, block=2000
                )
                if entries:
                    for _, messages in entries:
                        for msg_id, data in messages:
                            payload_str = data.get("data", "{}")
                            yield f"id: {msg_id}\ndata: {payload_str}\n\n"
                            last_delivered_id = msg_id

                            try:
                                parsed = json.loads(payload_str)
                                if isinstance(parsed, dict) and parsed.get("stage") in [
                                    "completed",
                                    "error",
                                ]:
                                    return
                            except (json.JSONDecodeError, TypeError) as parse_err:
                                logger.debug(
                                    "Non-JSON SSE payload skipped: %s", parse_err
                                )
                else:
                    # Send periodic keepalive comment every ~14 seconds to prevent 120s proxy timeout
                    keepalive_counter += 2
                    if keepalive_counter >= 14:
                        yield ": keepalive\n\n"
                        keepalive_counter = 0

            except asyncio.CancelledError:
                break
            except (OSError, RuntimeError, TimeoutError, ValueError) as loop_err:
                logger.error("SSE stream loop exception: %s", loop_err)
                await asyncio.sleep(1.0)

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/v1/trips/{correlation_id}")
async def get_trip_details(correlation_id: str, request: Request):
    """
    GET /trips/{id} endpoint returning stored trip result from Postgres/state DB
    with tenant isolation and ownership validation.
    """
    session_data = await session_manager.validate_request(request)
    tenant_id = session_data.get("tenant_id", "default")
    user_id = session_data["user_id"]

    trip = await get_trip_by_id(correlation_id, tenant_id=tenant_id)
    if not trip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Trip '{correlation_id}' not found.",
        )

    if (
        trip.get("user_id")
        and trip["user_id"] != user_id
        and "admin" not in session_data.get("roles", [])
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Trip belongs to another user.",
        )

    return trip


@app.post("/api/v1/admin/dlq/replay")
async def replay_dlq_messages(request: Request):
    """
    DLQ Replay Tool endpoint restricted to users with the 'admin' role.
    Reads failed messages from DLQ stream and re-publishes them to their original streams.
    """
    session_data = await session_manager.validate_request(request)
    roles = session_data.get("roles", [])
    if "admin" not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required for DLQ replay operations.",
        )

    r = await session_manager.get_redis()
    if not r:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    replayed = 0
    try:
        messages = await r.xrange("stream:travel:dlq", count=100)
        for msg_id, data in messages:
            orig_stream = data.get("original_stream")
            raw_event_data = data.get("data")
            if orig_stream and raw_event_data:
                parsed_data = json.loads(raw_event_data)
                raw_event_str = parsed_data.get("event", "{}")
                parsed_event = (
                    json.loads(raw_event_str)
                    if isinstance(raw_event_str, str)
                    else raw_event_str
                )
                ce = CloudEvent[Any](**parsed_event)
                await event_bus.publish(orig_stream, ce)
                await r.xdel("stream:travel:dlq", msg_id)
                replayed += 1
    except (
        OSError,
        RuntimeError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise HTTPException(status_code=500, detail=f"DLQ replay failed: {exc}")

    return {"status": "success", "replayed_count": replayed}
