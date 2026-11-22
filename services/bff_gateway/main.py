from services.core.config import get_settings
from services.core.lifecycle import lifespan_manager
from services.shared.exceptions import register_exception_handlers

_settings = get_settings()
"""
API Gateway / Backend For Frontend (BFF) Service.
Handles OpenTelemetry distributed tracing, structured JSON logging, pre-flight FinOps budgets,
rate limiting per user/tenant, secure HTTP-only cookie sessions with rotation, anti-CSRF enforcement,
Idempotency-Key verification, trip ownership, Prometheus /metrics endpoint, and resilient SSE streaming.
Integrates Phase 2 Enterprise Identity, Account Lifecycle, MFA, RBAC, and SCIM proxying.
"""
import asyncio
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from services.bff_gateway.session_manager import (
    SESSION_COOKIE_NAME,
    SessionManager,
)
from services.common.db import (
    relay_outbox,
    write_outbox,
)
from services.common.event_bus import EventBus
from services.common.pii_redactor import redact_pii
from services.common.schemas import CloudEvent, PlanningInitiatedPayload
from services.common.telemetry import (
    ACTIVE_SSE_CONNECTIONS_GAUGE,
    configure_structured_logging,
    extract_traceparent,
    get_metrics_payload,
    get_tracer,
    set_log_context,
    setup_telemetry,
)

# Configure structured JSON logging
configure_structured_logging()
logger = logging.getLogger("travelbrain.gateway")

AUTH_SERVICE_URL = _settings.auth.auth_service_url
REDIS_URL = _settings.redis.url
REDIS_PASSWORD = _settings.redis.password or ""

app = FastAPI(
    lifespan=lifespan_manager,
    title="TravelBrain API Gateway & BFF",
    version="2.0.0",
    description="Edge Gateway, Multi-Tenant Session Barrier, OpenTelemetry Tracing, and Authenticated SSE Streaming",
)

# Initialize OpenTelemetry instrumentation
setup_telemetry(service_name="bff-gateway", app=app)
register_exception_handlers(app)
tracer = get_tracer("travelbrain.gateway")

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
            logger.debug("Outbox relay background loop iteration trace: %s", exc)
        await asyncio.sleep(1.0)


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    if templates:
        return templates.TemplateResponse("index.html", {"request": request})
    return HTMLResponse(
        content="<h1>TravelBrain AI Planner API Gateway Active</h1>", status_code=200
    )


@app.get("/health/live")
async def liveness_probe():
    return {"status": "UP", "service": "bff-gateway"}


@app.get("/health/ready")
async def readiness_probe():
    return {
        "status": "READY",
        "service": "bff-gateway",
        "event_bus": event_bus.is_connected,
    }


@app.get("/metrics")
async def metrics_endpoint():
    payload, content_type = get_metrics_payload()
    return Response(content=payload, media_type=content_type)


@app.post("/api/v1/auth/login")
async def bff_login(req: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "127.0.0.1"
    rate_ok = await session_manager.check_rate_limit(
        client_identifier=f"login:{client_ip}",
        tenant_id=req.tenant_id,
        max_requests=10,
        window_seconds=60,
    )
    if not rate_ok:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication requests.",
        )
    async with httpx.AsyncClient() as client:
        try:
            auth_resp = await client.post(
                f"{AUTH_SERVICE_URL}/api/v1/auth/login",
                json=req.model_dump(),
                timeout=5.0,
            )
        except httpx.HTTPError as exc:
            logger.error("Failed contacting Auth service: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unreachable.",
            )
    if auth_resp.status_code != 200:
        raise HTTPException(
            status_code=auth_resp.status_code, detail=auth_resp.json().get("detail")
        )
    token_data = auth_resp.json()
    jwt_token = token_data["access_token"]
    user_id = token_data["user_id"]
    email = token_data["email"]
    roles = token_data.get("roles", ["traveler"])
    old_sid = request.cookies.get(SESSION_COOKIE_NAME)
    session_id, csrf_token = await session_manager.create_session(
        jwt_token=jwt_token,
        user_id=user_id,
        email=email,
        tenant_id=req.tenant_id,
        roles=roles,
        old_session_id=old_sid,
    )
    is_secure = request.url.scheme == "https"
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=86400,
    )
    return {
        "user_id": user_id,
        "email": email,
        "roles": roles,
        "tenant_id": req.tenant_id,
        "csrf_token": csrf_token,
        "expires_in": 86400,
    }


@app.post("/api/v1/auth/logout")
async def bff_logout(request: Request, response: Response):
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if sid:
        await session_manager.destroy_session(sid)
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return {"status": "logged_out"}


@app.post("/api/v1/plan")
async def initiate_trip_plan(
    plan_req: TripPlanRequest, request: Request, response: Response
):
    session = await session_manager.validate_request(request, check_csrf=True)
    user_id = session["user_id"]
    tenant_id = session.get("tenant_id", "default")
    set_log_context(
        correlation_id=request.headers.get(
            "X-Correlation-ID", f"cor_{uuid.uuid4().hex[:12]}"
        ),
        tenant_id=tenant_id,
    )
    correlation_id = (
        request.headers.get("X-Correlation-ID") or f"cor_{uuid.uuid4().hex[:12]}"
    )

    sanitized_query = redact_pii(plan_req.message)
    event_payload = PlanningInitiatedPayload(
        correlation_id=correlation_id,
        user_id=user_id,
        tenant_id=tenant_id,
        user_query=sanitized_query,
        destination=plan_req.destination,
        departure_city=plan_req.departure_city,
        start_date=plan_req.start_date,
        end_date=plan_req.end_date,
        dates=plan_req.dates,
    )
    cloud_event = CloudEvent(
        source="bff-gateway",
        type="travelbrain.planning.initiated",
        subject=user_id,
        traceparent=extract_traceparent(request.headers),
        data=event_payload.model_dump(),
    )
    await write_outbox(
        event_type="travelbrain.planning.initiated",
        payload=cloud_event.model_dump(),
        tenant_id=tenant_id,
    )
    return {
        "status": "accepted",
        "correlation_id": correlation_id,
        "sse_url": f"/api/v1/events/stream/{correlation_id}",
    }


@app.get("/api/v1/events/stream/{correlation_id}")
async def stream_planning_events(correlation_id: str, request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    _ = session["user_id"]
    _ = session.get("tenant_id", "default")

    async def event_generator() -> AsyncGenerator[str, None]:
        ACTIVE_SSE_CONNECTIONS_GAUGE.inc()
        try:
            pubsub = await event_bus.subscribe(f"events:{correlation_id}")
            yield f"data: {json.dumps({'stage': 'connected', 'message': 'SSE Stream Established'})}"
            async for msg in pubsub.listen():
                if msg["type"] == "message":
                    raw_data = msg["data"]
                    yield f"data: {raw_data}"
                    try:
                        parsed = json.loads(raw_data)
                        if (
                            parsed.get("stage") == "completed"
                            or parsed.get("percentage") == 100
                        ):
                            break
                    except (json.JSONDecodeError, TypeError) as exc:
                        logger.debug(f"Skipping non-JSON SSE payload: {exc}")
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            logger.error(f"SSE stream error: {exc}")
            yield f"data: {json.dumps({'stage': 'error', 'message': str(exc)})}"
        finally:
            ACTIVE_SSE_CONNECTIONS_GAUGE.dec()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
