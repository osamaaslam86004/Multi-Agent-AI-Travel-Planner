"""
API Gateway / Backend For Frontend (BFF) Service.
Handles OpenTelemetry distributed tracing, structured JSON logging, pre-flight FinOps budgets,
rate limiting per user/tenant, secure HTTP-only cookie sessions with rotation, anti-CSRF enforcement,
Idempotency-Key verification, trip access ACLs, Prometheus /metrics endpoint, and resilient SSE streaming.
Integrates Phase 2 Enterprise Identity MFA challenges, provider linking, invitations, soft-deletion, and security events.
"""

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from services.bff_gateway.session_manager import (
    SESSION_COOKIE_NAME,
    SessionManager,
)
from services.common.db import (
    db_can_access_trip,
    db_get_login_history,
    db_list_user_trips,
    get_trip_by_id,
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
from services.core.config import get_settings
from services.core.lifecycle import lifespan_manager
from services.shared.exceptions import register_exception_handlers

configure_structured_logging()
logger = logging.getLogger("travelbrain.gateway")
_settings = get_settings()
AUTH_SERVICE_URL = _settings.auth.auth_service_url
REDIS_URL = _settings.redis.url
REDIS_PASSWORD = _settings.redis.password or ""
COOKIE_NAME = _settings.security.session_cookie_name or SESSION_COOKIE_NAME
session_manager = SessionManager(redis_url=REDIS_URL, password=REDIS_PASSWORD)
event_bus = EventBus(redis_url=REDIS_URL, password=REDIS_PASSWORD)


async def periodic_outbox_relay():
    while True:
        try:
            await relay_outbox(event_bus)
        except Exception as exc:
            logger.debug(f"Outbox relay background loop iteration trace: {exc}")
        await asyncio.sleep(1.0)


@asynccontextmanager
async def bff_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    async with lifespan_manager(app):
        try:
            await event_bus.connect()
            logger.info("BFF Gateway connected to Redis Event Bus.")
        except Exception as exc:
            logger.warning(f"BFF Gateway startup event bus connect fallback: {exc}")
        relay_task = asyncio.create_task(periodic_outbox_relay())
        try:
            yield
        finally:
            relay_task.cancel()
            await event_bus.close()


app = FastAPI(
    lifespan=bff_lifespan,
    title="TravelBrain API Gateway & BFF",
    version="2.0.0",
    description="Edge Gateway, Multi-Tenant Session Barrier, OpenTelemetry Tracing, and Authenticated SSE Streaming",
)
setup_telemetry(service_name="bff-gateway", app=app)
register_exception_handlers(app)
tracer = get_tracer("travelbrain.gateway")
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


class MFAVerifyRequest(BaseModel):
    mfa_challenge_token: str
    totp_code: str | None = None
    backup_code: str | None = None


class TripShareWebRequest(BaseModel):
    grantee_id: str
    permission_level: str = "read"
    expires_at: str | None = None


class InvitationWebRequest(BaseModel):
    email: str
    org_id: str
    role: str = "member"


class InvitationAcceptWebRequest(BaseModel):
    token: str
    password: str | None = None
    display_name: str | None = None


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


@app.get("/api/v1/auth/me")
async def get_current_session_user(request: Request):
    try:
        session = await session_manager.validate_request(request, check_csrf=False)
        return {
            "authenticated": True,
            "user_id": session.get("user_id"),
            "email": session.get("email"),
            "tenant_id": session.get("tenant_id", "default"),
            "roles": session.get("roles", "traveler").split(","),
            "csrf_token": session.get("csrf_token"),
        }
    except HTTPException:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"authenticated": False, "detail": "Unauthenticated"},
        )


# Direct Login Route with MFA challenge support
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
            logger.error(f"Failed contacting Auth service: {exc}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unreachable.",
            )
    if auth_resp.status_code != 200:
        raise HTTPException(
            status_code=auth_resp.status_code, detail=auth_resp.json().get("detail")
        )
    token_data = auth_resp.json()
    if token_data.get("mfa_required"):
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "mfa_required": True,
                "mfa_challenge_token": token_data.get("mfa_challenge_token"),
                "mfa_methods": token_data.get("mfa_methods", ["totp", "backup_code"]),
                "user_id": token_data.get("user_id"),
            },
        )
    jwt_token = token_data["access_token"]
    user_id = token_data["user_id"]
    email = token_data["email"]
    roles = token_data.get("roles", ["traveler"])
    resolved_tenant = token_data.get("tenant_id", req.tenant_id)
    old_sid = request.cookies.get(COOKIE_NAME)
    session_id, csrf_token = await session_manager.create_session(
        jwt_token=jwt_token,
        user_id=user_id,
        email=email,
        tenant_id=resolved_tenant,
        roles=roles,
        old_session_id=old_sid,
    )
    is_secure = request.url.scheme == "https" or _settings.security.cookie_secure
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=is_secure,
        samesite=_settings.security.cookie_samesite or "lax",
        max_age=86400,
    )
    return {
        "authenticated": True,
        "user_id": user_id,
        "email": email,
        "roles": roles,
        "tenant_id": resolved_tenant,
        "csrf_token": csrf_token,
        "expires_in": 86400,
    }


# MFA Verification Route
@app.post("/api/v1/auth/mfa/verify")
async def bff_mfa_verify(req: MFAVerifyRequest, request: Request, response: Response):
    async with httpx.AsyncClient() as client:
        try:
            auth_resp = await client.post(
                f"{AUTH_SERVICE_URL}/api/v1/auth/mfa/verify-login",
                json=req.model_dump(),
                timeout=5.0,
            )
        except httpx.HTTPError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unreachable.",
            )
    if auth_resp.status_code != 200:
        raise HTTPException(
            status_code=auth_resp.status_code,
            detail=auth_resp.json().get("detail", "MFA verification failed"),
        )
    token_data = auth_resp.json()
    jwt_token = token_data["access_token"]
    user_id = token_data["user_id"]
    email = token_data["email"]
    roles = token_data.get("roles", ["traveler"])
    resolved_tenant = token_data.get("tenant_id", "default")
    old_sid = request.cookies.get(COOKIE_NAME)
    session_id, csrf_token = await session_manager.create_session(
        jwt_token=jwt_token,
        user_id=user_id,
        email=email,
        tenant_id=resolved_tenant,
        roles=roles,
        old_session_id=old_sid,
    )
    is_secure = request.url.scheme == "https" or _settings.security.cookie_secure
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=is_secure,
        samesite=_settings.security.cookie_samesite or "lax",
        max_age=86400,
    )
    return {
        "authenticated": True,
        "user_id": user_id,
        "email": email,
        "roles": roles,
        "tenant_id": resolved_tenant,
        "csrf_token": csrf_token,
        "expires_in": 86400,
    }


# OIDC authorization transaction
@app.get("/api/v1/auth/{provider}/login")
async def oidc_login_initiate(
    provider: str,
    request: Request,
    redirect_uri: str | None = None,
    org_id: str | None = None,
):
    if provider not in {"google", "entra", "github", "generic_oidc"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    callback_uri = redirect_uri or str(
        request.url_for("oidc_callback", provider=provider)
    )
    parsed_callback = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(
        callback_uri
    )
    parsed_origin = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(
        str(request.base_url)
    )
    if (
        parsed_callback.scheme not in ("https", "http")
        or parsed_callback.netloc != parsed_origin.netloc
    ):
        raise HTTPException(status_code=400, detail="Redirect URI must be same-origin")
    async with httpx.AsyncClient() as client:
        try:
            auth_response = await client.get(
                f"{AUTH_SERVICE_URL}/api/v1/auth/oidc/authorize-url",
                params={
                    "provider": provider,
                    "redirect_uri": callback_uri,
                    "org_id": org_id or "",
                },
                timeout=8.0,
            )
            auth_response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="Auth service authorization initiation unavailable",
            ) from exc
    return RedirectResponse(url=auth_response.json()["authorization_url"])


@app.get("/api/v1/auth/{provider}/callback")
async def oidc_callback(provider: str, code: str, state: str, request: Request):
    redirect_uri = str(request.url_for("oidc_callback", provider=provider))
    exchange_payload = {
        "provider": provider,
        "code": code,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{AUTH_SERVICE_URL}/api/v1/auth/oidc/login",
                json=exchange_payload,
                timeout=8.0,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503, detail="Auth service unavailable"
            ) from exc
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code,
            detail=resp.json().get("detail", "OIDC login failed"),
        )
    token_data = resp.json()
    if token_data.get("mfa_required"):
        return RedirectResponse(
            url=f"/#mfa?token={token_data.get('mfa_challenge_token')}", status_code=302
        )
    old_sid = request.cookies.get(COOKIE_NAME)
    session_id, _csrf_token = await session_manager.create_session(
        jwt_token=token_data["access_token"],
        user_id=token_data["user_id"],
        email=token_data["email"],
        tenant_id=token_data.get("tenant_id", "default"),
        roles=token_data.get("roles", ["traveler"]),
        old_session_id=old_sid,
    )
    redirect_resp = RedirectResponse(url="/", status_code=302)
    is_secure = request.url.scheme == "https" or _settings.security.cookie_secure
    redirect_resp.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=86400,
    )
    return redirect_resp


@app.post("/api/v1/auth/logout")
async def bff_logout(request: Request, response: Response):
    session = await session_manager.validate_request(request, check_csrf=True)
    sid = request.cookies.get(COOKIE_NAME)
    if sid:
        async with httpx.AsyncClient() as client:
            try:
                upstream = await client.post(
                    f"{AUTH_SERVICE_URL}/api/v1/users/me/sessions/revoke",
                    json={"session_id": sid},
                    headers={"Authorization": f"Bearer {session.get('jwt')}"},
                    timeout=5.0,
                )
                upstream.raise_for_status()
            except httpx.HTTPError as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Upstream revocation failed; session remains active",
                ) from exc
        await session_manager.destroy_session(
            sid, tenant_id=session.get("tenant_id", "default")
        )
    response.delete_cookie(key=COOKIE_NAME)
    return {"status": "logged_out"}


# Provider Linking Proxies
@app.post("/api/v1/users/me/providers/link")
async def proxy_link_provider(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    body = await request.json()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{AUTH_SERVICE_URL}/api/v1/users/me/providers/link",
            json=body,
            headers={"Authorization": f"Bearer {session.get('jwt')}"},
            timeout=5.0,
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code, detail=resp.json().get("detail")
        )
    return resp.json()


@app.delete("/api/v1/users/me/providers/unlink/{provider}")
async def proxy_unlink_provider(provider: str, request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    async with httpx.AsyncClient() as client:
        resp = await client.delete(
            f"{AUTH_SERVICE_URL}/api/v1/users/me/providers/{provider}",
            headers={"Authorization": f"Bearer {session.get('jwt')}"},
            timeout=5.0,
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code, detail=resp.json().get("detail")
        )
    return resp.json()


# Account Soft-Deletion Proxies
@app.post("/api/v1/users/me/delete-account")
async def proxy_delete_account(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    async with httpx.AsyncClient() as client:
        resp = await client.delete(
            f"{AUTH_SERVICE_URL}/api/v1/users/me",
            headers={"Authorization": f"Bearer {session.get('jwt')}"},
            timeout=5.0,
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code, detail=resp.json().get("detail")
        )
    return resp.json()


@app.post("/api/v1/users/me/cancel-deletion")
async def proxy_cancel_deletion(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{AUTH_SERVICE_URL}/api/v1/users/me/cancel-deletion",
            headers={"Authorization": f"Bearer {session.get('jwt')}"},
            timeout=5.0,
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code, detail=resp.json().get("detail")
        )
    return resp.json()


# Security Events & Device Management Proxies
@app.get("/api/v1/users/me/security-events")
async def proxy_security_events(request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    history = await db_get_login_history(session.get("user_id"), limit=50)
    return {"security_events": history}


@app.get("/api/v1/users/me/sessions")
async def proxy_list_sessions(request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    sessions = await session_manager.list_user_sessions(
        session.get("user_id"), session.get("tenant_id", "default")
    )
    return {
        "sessions": sessions,
        "current_session_id": request.cookies.get(COOKIE_NAME),
    }


@app.delete("/api/v1/users/me/sessions/{sid}")
async def proxy_revoke_session(sid: str, request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    target = await session_manager.get_session(
        sid, tenant_id=session.get("tenant_id", "default")
    )
    if not target or target.get("user_id") != session.get("user_id"):
        raise HTTPException(status_code=404, detail="Session not found")
    async with httpx.AsyncClient() as client:
        try:
            upstream = await client.post(
                f"{AUTH_SERVICE_URL}/api/v1/users/me/sessions/revoke",
                json={"session_id": sid},
                headers={"Authorization": f"Bearer {session.get('jwt')}"},
                timeout=5.0,
            )
            upstream.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503, detail="Upstream token revocation unavailable"
            ) from exc
    await session_manager.revoke_session(
        sid, tenant_id=session.get("tenant_id", "default")
    )
    return {"status": "revoked", "session_id": sid}


@app.post("/api/v1/users/me/logout-all")
async def proxy_logout_all(request: Request, response: Response):
    session = await session_manager.validate_request(request, check_csrf=True)
    async with httpx.AsyncClient() as client:
        try:
            upstream = await client.post(
                f"{AUTH_SERVICE_URL}/api/v1/users/me/logout-all",
                headers={"Authorization": f"Bearer {session.get('jwt')}"},
                timeout=5.0,
            )
            upstream.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="Upstream logout-all unavailable; local sessions preserved",
            ) from exc
    await session_manager.logout_user_all_devices(
        session.get("user_id"), tenant_id=session.get("tenant_id", "default")
    )
    response.delete_cookie(key=COOKIE_NAME)
    return {"status": "logged_out_all"}


# Trip Planning & Outbox
@app.post("/api/v1/trips/plan")
@app.post("/api/v1/plan")
async def initiate_trip_plan(
    plan_req: TripPlanRequest, request: Request, response: Response
):
    session = await session_manager.validate_request(request, check_csrf=True)
    user_id = session["user_id"]
    tenant_id = session.get("tenant_id", "default")
    correlation_id = (
        request.headers.get("X-Correlation-ID") or f"cor_{uuid.uuid4().hex[:12]}"
    )
    set_log_context(correlation_id=correlation_id, tenant_id=tenant_id)
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
    CloudEvent(
        source="bff-gateway",
        type="travelbrain.planning.initiated",
        subject=user_id,
        traceparent=extract_traceparent(request.headers),
        data=event_payload.model_dump(),
    )
    await write_outbox(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        stream_name="stream:travel:planning:initiated",
        event_type="travelbrain.planning.initiated",
        payload=event_payload.model_dump(),
    )
    return {
        "status": "accepted",
        "correlation_id": correlation_id,
        "sse_url": f"/api/v1/events/stream/{correlation_id}",
        "stream_url": f"/api/v1/events/stream/{correlation_id}",
    }


# Trip CRUD & Access Control Routes
@app.get("/api/v1/trips")
async def list_trips(request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    user_id, tenant_id = session["user_id"], session.get("tenant_id", "default")
    trips = await db_list_user_trips(user_id, tenant_id=tenant_id)
    return {"trips": trips}


@app.get("/api/v1/trips/{correlation_id}")
async def get_trip(correlation_id: str, request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    user_id, tenant_id = session["user_id"], session.get("tenant_id", "default")
    if not await db_can_access_trip(user_id, correlation_id, tenant_id, action="read"):
        raise HTTPException(status_code=404, detail="Trip not found or access denied")
    trip = await get_trip_by_id(correlation_id, tenant_id=tenant_id)
    return trip


@app.post("/api/v1/trips/{correlation_id}/share")
async def share_trip(correlation_id: str, req: TripShareWebRequest, request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    user_id, tenant_id = session["user_id"], session.get("tenant_id", "default")
    if not await db_can_access_trip(user_id, correlation_id, tenant_id, action="share"):
        raise HTTPException(status_code=403, detail="Trip sharing permission denied")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{AUTH_SERVICE_URL}/api/v1/trips/share",
            json={
                "trip_id": correlation_id,
                "grantee_id": req.grantee_id,
                "permission_level": req.permission_level,
                "expires_at": req.expires_at,
            },
            headers={"Authorization": f"Bearer {session.get('jwt')}"},
            timeout=5.0,
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code, detail=resp.json().get("detail")
        )
    return resp.json()


# SSE Streaming Route
@app.get("/api/v1/trips/{correlation_id}/stream")
@app.get("/api/v1/events/stream/{correlation_id}")
async def stream_planning_events(correlation_id: str, request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    user_id, tenant_id = session["user_id"], session.get("tenant_id", "default")
    if not await db_can_access_trip(user_id, correlation_id, tenant_id, action="read"):
        raise HTTPException(status_code=404, detail="Trip not found or access denied")

    async def event_generator() -> AsyncGenerator[str, None]:
        ACTIVE_SSE_CONNECTIONS_GAUGE.inc()
        try:
            pubsub = await event_bus.subscribe(f"events:{correlation_id}")
            yield f"data: {json.dumps({'stage': 'connected', 'message': 'SSE Stream Established'})}\n\n"
            async for msg in pubsub.listen():
                if msg["type"] == "message":
                    raw_data = msg["data"]
                    yield f"data: {raw_data}\n\n"
                    try:
                        parsed = json.loads(raw_data)
                        if (
                            parsed.get("stage") in ("completed", "synthesis_completed")
                            or parsed.get("percentage") == 100
                        ):
                            break
                    except Exception:
                        pass
        except Exception as exc:
            logger.error(f"SSE stream error for trip {correlation_id}: {exc}")
            yield f"data: {json.dumps({'stage': 'error', 'message': str(exc)})}\n\n"
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


# --- Added P0 Comprehensive Identity & Auth BFF Proxies ---


@app.get("/api/v1/auth/profile")
async def bff_get_profile(request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    if "x-sudo-token" in request.headers:
        headers["X-Sudo-Token"] = request.headers["x-sudo-token"]
    resp = await http_client.get(f"{AUTH_SERVICE_URL}/api/v1/users/me", headers=headers)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code,
            detail=resp.json().get("detail", "Profile fetch failed"),
        )
    return resp.json()


@app.put("/api/v1/auth/profile")
async def bff_update_profile(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    body = await request.json()
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    if "x-sudo-token" in request.headers:
        headers["X-Sudo-Token"] = request.headers["x-sudo-token"]
    resp = await http_client.put(
        f"{AUTH_SERVICE_URL}/api/v1/users/me", json=body, headers=headers
    )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code,
            detail=resp.json().get("detail", "Profile update failed"),
        )
    return resp.json()


@app.post("/api/v1/auth/magic-link")
async def bff_magic_link_request(request: Request):
    body = await request.json()
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/auth/magic-link", json=body
    )
    return (
        resp.json()
        if resp.status_code == 200
        else Response(content=resp.content, status_code=resp.status_code)
    )


@app.post("/api/v1/auth/magic-link/verify")
async def bff_magic_link_verify(request: Request, response: Response):
    body = await request.json()
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/auth/magic-link/verify", json=body
    )
    if resp.status_code == 200:
        data = resp.json()
        sid, csrf = await session_manager.create_session(
            jwt_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            user_id=data["user_id"],
            email=data["email"],
            roles=data.get("roles", []),
        )
        response.set_cookie(
            key=SESSION_COOKIE_NAME, value=sid, httponly=True, samesite="lax"
        )
        return {"authenticated": True, "csrf_token": csrf, "user_id": data["user_id"]}
    raise HTTPException(
        status_code=resp.status_code,
        detail=resp.json().get("detail", "Magic link verification failed"),
    )


@app.post("/api/v1/auth/password-reset/request")
async def bff_password_reset_request(request: Request):
    body = await request.json()
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/recovery", json=body
    )
    return Response(content=resp.content, status_code=resp.status_code)


@app.post("/api/v1/auth/password-reset/confirm")
async def bff_password_reset_confirm(request: Request):
    body = await request.json()
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/recovery/confirm", json=body
    )
    return Response(content=resp.content, status_code=resp.status_code)


@app.post("/api/v1/auth/verify-email/request")
async def bff_verify_email_request(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/verify-email/request", headers=headers
    )
    return Response(content=resp.content, status_code=resp.status_code)


@app.post("/api/v1/auth/verify-email/confirm")
async def bff_verify_email_confirm(request: Request):
    body = await request.json()
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/verify-email/confirm", json=body
    )
    return Response(content=resp.content, status_code=resp.status_code)


@app.post("/api/v1/auth/invitations")
async def bff_create_invitation(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    body = await request.json()
    org_id = body.get("org_id", "default")
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    if "x-sudo-token" in request.headers:
        headers["X-Sudo-Token"] = request.headers["x-sudo-token"]
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/orgs/{org_id}/invitations",
        json=body,
        headers=headers,
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/invitations/accept")
async def bff_accept_invitation(request: Request):
    body = await request.json()
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/invitations/accept", json=body
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/mfa/enroll")
async def bff_mfa_enroll(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/me/mfa/enroll", headers=headers
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/mfa/verify-enrollment")
async def bff_mfa_verify_enrollment(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    body = await request.json()
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/me/mfa/verify", json=body, headers=headers
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/mfa/disable")
async def bff_mfa_disable(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    body = await request.json()
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    if "x-sudo-token" in request.headers:
        headers["X-Sudo-Token"] = request.headers["x-sudo-token"]
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/me/mfa/disable", json=body, headers=headers
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/reauthenticate")
async def bff_reauthenticate(request: Request):
    session = await session_manager.validate_request(request, check_csrf=True)
    body = await request.json()
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/auth/reauthenticate", json=body, headers=headers
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/refresh")
async def bff_refresh_tokens(request: Request, response: Response):
    session = await session_manager.validate_request(request, check_csrf=False)
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token in session")
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    if resp.status_code == 200:
        data = resp.json()
        new_sid, new_csrf = await session_manager.create_session(
            jwt_token=data["access_token"],
            refresh_token=data.get("refresh_token", refresh_token),
            user_id=data["user_id"],
            email=data["email"],
            roles=data.get("roles", []),
            old_session_id=session["session_id"],
        )
        response.set_cookie(
            key=SESSION_COOKIE_NAME, value=new_sid, httponly=True, samesite="lax"
        )
        return {"status": "refreshed", "csrf_token": new_csrf}
    raise HTTPException(status_code=resp.status_code, detail="Token refresh failed")


@app.get("/api/v1/auth/organizations")
async def bff_list_orgs(request: Request):
    session = await session_manager.validate_request(request, check_csrf=False)
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    resp = await http_client.get(
        f"{AUTH_SERVICE_URL}/api/v1/users/me/orgs", headers=headers
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/organizations/switch")
async def bff_switch_org(request: Request, response: Response):
    session = await session_manager.validate_request(request, check_csrf=True)
    body = await request.json()
    headers = {"Authorization": f"Bearer {session['jwt']}"}
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/users/me/switch-org", json=body, headers=headers
    )
    if resp.status_code == 200:
        data = resp.json()
        new_sid, new_csrf = await session_manager.create_session(
            jwt_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            user_id=data["user_id"],
            email=data["email"],
            tenant_id=body.get("org_id", "default"),
            roles=data.get("roles", []),
            old_session_id=session["session_id"],
        )
        response.set_cookie(
            key=SESSION_COOKIE_NAME, value=new_sid, httponly=True, samesite="lax"
        )
        return {
            "status": "switched",
            "csrf_token": new_csrf,
            "roles": data.get("roles", []),
        }
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/sso/discover")
async def bff_sso_discover(request: Request):
    body = await request.json()
    resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/auth/sso/discover", json=body
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/api/v1/auth/saml/acs")
async def bff_saml_acs(request: Request, response: Response):
    form_data = await request.form()
    saml_resp = form_data.get("SAMLResponse")
    relay_state = form_data.get("RelayState", "/")

    upstream_resp = await http_client.post(
        f"{AUTH_SERVICE_URL}/api/v1/auth/saml/acs",
        data={"SAMLResponse": saml_resp, "RelayState": relay_state},
    )
    if upstream_resp.status_code == 200:
        data = upstream_resp.json()
        sid, _csrf = await session_manager.create_session(
            jwt_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            user_id=data["user_id"],
            email=data["email"],
            roles=data.get("roles", []),
        )
        response.set_cookie(
            key=SESSION_COOKIE_NAME, value=sid, httponly=True, samesite="lax"
        )
        target_url = relay_state if relay_state and relay_state.startswith("/") else "/"
        return RedirectResponse(url=target_url, status_code=302)
