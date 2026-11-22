# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.7.2] - 2026-11-22
## [1.7.2] - 2026-11-22

### Added
- **Durable Identity Schema, Migrations & Persistence Layer (`migrations/`, `services/auth_service/user_lifecycle.py`, `services/auth_service/enterprise.py`, `services/common/db.py`)**:
  - Added database migrations and repository persistence for `user_profiles`, `federated_identities`, `login_history`, `orgs`, `org_memberships`, `role_assignments`, `idp_configs`, `scim_tokens`, and `scim_groups` with `tenant_id` scoping and Row-Level Security (RLS), replacing process-local identity state dictionaries[cite: 1].
  - Replaced placeholder `users` row inserts in `common/db.py` with real profile foreign keys/references[cite: 1].
- **Refresh Token Rotation, Revocation Registry & Token Typing (`services/auth_service/main.py`, `services/auth_service/security.py`, `services/common/auth_middleware.py`)**:
  - Added explicit `token_use` claims (`access` vs. `refresh`) and implemented `/auth/refresh` with refresh token rotation, token family tracking, stored `jti` hashes, and reuse detection with family revocation[cite: 1].
  - Implemented real token and session revocation in Redis (`revoked:{jti}`, `revoked:sid:{sid}`, and per-user `tokens_valid_after:{user_id}`) using the shared password-aware Redis client (`services.shared.redis_client.get_redis_client()`) with fail-closed (`503`) handling in `production` when Redis is unreachable[cite: 1].
- **Federated Identity Linking & OIDC Protocol Security (`services/auth_service/adapters.py`, `services/auth_service/main.py`, `services/auth_service/enterprise.py`)**:
  - Added `federated_identities` binding external identities to `(provider, issuer, sub)` (and Entra `tid` + `oid`), requiring verified email for first-time account creation and restricting automatic linking to verified emails from trusted domains/providers[cite: 1].
  - Added server-side `state`, `nonce`, and PKCE validation bound to short-lived pre-sessions, enforced `aud`/`iss`/`nonce` validation (including Entra issuer/tenant checks), offloaded blocking JWKS lookups via `asyncio.to_thread`, and sanitized upstream/validation error responses[cite: 1].
- **BFF OIDC Flows, Canonical Sessions & Frontend Identity UI (`services/bff_gateway/main.py`, `services/bff_gateway/session_manager.py`, `frontend/static/js/app.js`, `frontend/`)**:
  - Added BFF OIDC login and callback routes (`GET /api/v1/auth/{provider}/login`, `GET .../callback`), `GET /api/v1/auth/me` with CSRF token delivery, and session management endpoints (`/users/me/sessions`, `DELETE .../sessions/{sid}`, and logout-all) wired to token/session revocation[cite: 1].
  - Unified session IDs (`sid`) across BFF sessions and JWTs using canonical `session:{tenant}:{sid}` records and `user_sessions:{tenant}:{user}` indexes with sliding idle timeout[cite: 1].
  - Updated frontend client and views to align with BFF routes and stream fields (`stream_url` / `sse_url`, CSRF headers), removed the false `"Guest Mode"` fallback when unauthenticated, and added login, profile, and session views[cite: 1].

### Changed
- **Startup Config, Secret Validation & Cross-Service Wiring (`k8s/`, `docker-compose.yml`, `services/bff_gateway/main.py`, `services/common/event_bus.py`, `services/weather_service/worker.py`)**:
  - Provisioned required secrets (including `JWT_SECRET_KEY`, `SCIM_TOKEN_SECRET`, and `JWT_PRIVATE_KEY_PEM`) in `production` manifests and `docker-compose.yml`, made startup validation role-aware for workers, and enforced fail-fast checks on missing keys or insecure defaults[cite: 1].
  - Fixed `initiate_trip_plan` `write_outbox` arguments, moved `periodic_outbox_relay` startup into `lifespan` handling, aligned SSE streaming channels/framing and `/health/ready` checks, fixed `EventBus.__init__` credential handling for workers, replaced `search_weather` with `get_weather`, and repaired `docker-compose.yml` structure and volume declarations[cite: 1].
  - Fixed Kubernetes `NetworkPolicy` selectors (`redis-broker-service`, `redis-cache-service`) and DNS/service/DB/Redis egress rules[cite: 1].
- **Signing Key Lifecycle & Endpoint Authentication (`services/auth_service/security.py`, `services/auth_service/main.py`)**:
  - Loaded primary and previous RSA signing keys from settings/secrets at startup, aborted startup when the primary key is missing in `staging` or `production`, retained previous keys in JWKS for at least max token TTL with `Cache-Control` headers, and switched auth service token checks to local public-key verification[cite: 1].
  - Required authentication and derived acting identity from verified tokens on account, MFA, reauth, and RBAC routes instead of caller-supplied `user_id` or role lists, and enforced SCIM bearer token verification (`hmac.compare_digest`), IdP config authorization, and domain ownership proof[cite: 1].
- **Central Login Policy Gate, Account Status & Server-Side Tenant Resolution (`services/auth_service/main.py`, `services/auth_service/user_lifecycle.py`, `services/bff_gateway/main.py`)**:
  - Enforced central login policy evaluation (SSO enforcement and domain-to-org mapping), account status checks across all login paths, server-side tenant resolution instead of client-supplied `tenant_id`, and strict gating of dev login via `enable_dev_login` forbidden in `staging` and `production`[cite: 1].
  - Removed `O(N)` `redis.keys(...)` session lookups and production in-memory session fallbacks, and aligned session cookie configuration[cite: 1].


## [1.7.1] - 2026-11-22

### Added
- **Centralized `pydantic-settings` Configuration & Fail-Fast Validation (`services/core/config/`, `services/*/`)**:
  - Implemented centralized settings management using `pydantic-settings` with dedicated sub-configuration models for application, authentication, database, Redis, LLM providers, MCP integrations, observability, security, rate limits, and deployment.
  - Added environment profile awareness (`development`, `staging`, `production`) with startup validation, fail-fast enforcement for invalid production configurations, configurable timeout/retry/concurrency settings, standardized naming conventions, and safe configuration reload support where applicable[cite: 6].
- **Standardized Service & Worker Lifecycles (`services/core/lifecycle/`, `services/*/main.py`, `services/*/worker.py`)**:
  - Standardized FastAPI application lifespan handling and worker startup/shutdown lifecycles while preventing resource initialization at module import time[cite: 6].
  - Centralized initialization and graceful teardown—with configurable shutdown deadlines and pending-work release—for Redis clients, PostgreSQL pools, HTTP clients, MCP sessions, OpenTelemetry, and provider clients[cite: 6].
- **Versioned Internal Service Contracts & Schemas (`services/contracts/`, `services/common/schemas.py`)**:
  - Standardized API response and error response envelopes, defined internal service API contracts with explicit ownership and responsibility boundaries, and separated domain schemas from transport schemas[cite: 6].
  - Added API and event payload contract versioning along with shared schema compatibility rules[cite: 6].
- **Shared Architecture Cleanup & Centralized Feature Flags (`services/core/feature_flags.py`, `services/shared/redis_client.py`, `services/shared/http_client.py`, `services/common/`)**:
  - Eliminated duplicated Redis and HTTP client initialization across modules, standardized dependency injection and logging/exception handling, and added centralized feature flag infrastructure alongside service-specific settings and architectural conventions for new services[cite: 6].

### Changed
- **Environment Variable & Client Consolidation (`services/`)**:
  - Removed scattered `os.getenv()` calls across service modules in favor of typed centralized settings and shared client/lifecycle utilities[cite: 6].



## [1.7.0] - 2026-11-21

### Added
- **End-to-End OpenTelemetry SDK, OTLP Exporter & Structured JSON Logging (`services/common/telemetry.py`, `services/common/event_bus.py`, `services/bff_gateway/main.py`)**:
  - Configured a real OpenTelemetry `TracerProvider` with OTLP export and automatic instrumentation for FastAPI, `httpx`, and Redis (`opentelemetry-instrumentation-fastapi`, `opentelemetry-instrumentation-httpx`, `opentelemetry-instrumentation-redis`), replacing inert API-only no-op tracing.
  - Extracted incoming W3C `traceparent` headers into active OpenTelemetry contexts inside event bus consumer handlers and started root spans at the BFF gateway so distributed spans correlate end-to-end across HTTP and Redis Streams.
  - Added structured JSON logging enriched with `trace_id`, `correlation_id`, and `tenant_id` across services and workers.
- **Prometheus Metrics & Observability Instrumentation (`pyproject.toml`, `services/common/metrics.py`, `services/bff_gateway/main.py`, `services/*/worker.py`)**:
  - Added `prometheus-client` to project dependencies in `pyproject.toml` and exposed Prometheus metrics endpoints across gateway and worker services.
  - Instrumented stream lag, pending-entry list (PEL) age, synthesis barrier age, circuit breaker states (`CLOSED`/`HALF_OPEN`/`OPEN`), degraded response ratios, active SSE connections, and per-tenant token and cost accounting with bounded label cardinality.
- **FinOps Token Accounting, Pre-Flight Tenant Budgets & Prompt Controls (`services/common/db.py`, `services/synthesis_service/synthesizer.py`, `services/synthesis_service/worker.py`, `services/bff_gateway/main.py`)**:
  - Persisted `LLMResult.token_usage`, `provider`, `model`, and estimated cost into `llm_usage` and attached usage metadata to synthesis event payloads.
  - Enforced pre-flight per-tenant token/cost budget quotas before dispatching planning workflows, capped input prompt sizes and `max_tokens`, and supported routing cheaper models for drafting stages.
- **Kubernetes Autoscaling, Pod Disruption Budgets & Graceful Drain (`k8s/keda-scaledobjects.yaml`, `k8s/bff-gateway.yaml`, `k8s/domain-workers.yaml`, `k8s/pdb.yaml`, `k8s/ingress.yaml`)**:
  - Added KEDA `ScaledObject` definitions scaling domain workers on Redis Stream lag and scaling `bff-gateway` on active SSE connections rather than CPU utilization.
  - Added Pod Disruption Budgets (`PDB`), pod topology spread / anti-affinity rules, worker health probes, extended `terminationGracePeriodSeconds`, and `preStop` drain hooks so in-flight stream consumers complete cleanly before termination.
  - Migrated Ingress configuration from deprecated `kubernetes.io/ingress.class` annotations to `spec.ingressClassName` and removed unused WebSocket annotations.
- **Dependencies, Lockfile & Code Quality Verification (`pyproject.toml`, `uv.lock`, `requirements.txt`)**:
  - Added `prometheus-client` (alongside OpenTelemetry SDK/instrumentation packages) to `pyproject.toml`, regenerated `uv.lock`, and exported updated pinned dependencies to `requirements.txt`.
  - Verified all changes pass `ruff check .` and `ruff format --check .` cleanly.

### Changed
- **LLM Fallback Tier Architecture & Distributed Circuit Breakers (`services/common/llm_provider.py`, `services/common/resilient_chain.py`, `services/common/resilience.py`, `k8s/llm-inference.yaml`)**:
  - Overhauled Tier 3 local LLM execution to target an external quantized (4-bit) vLLM or Ollama inference endpoint (with configurable second cloud provider fallback) instead of running blocking in-process Hugging Face model loads inside async workers, removing the silent canned `_offline_fallback_generation` so exhausted chains surface honest degraded signals.
  - Fixed local `/chat/completions` message formatting to send structured role messages without double-applying ChatML templates and corrected model tag handling.
  - Shared circuit breaker state across replicas in Redis, enforced single-probe concurrency in `HALF_OPEN` state, excluded configuration `ValueError` exceptions from tripping breakers, respected `Retry-After` headers, and eliminated duplicate nested outer/inner breaker wrapping.



## [1.6.0] - 2026-11-20

### Added
- **PostgreSQL Transactional Outbox & Persistent Trip Store (`services/common/db.py`, `services/trip_store/worker.py`, `services/bff_gateway/main.py`)**:
  - Added async `psycopg_pool` connection management with tenant Row-Level Security (`SET LOCAL app.current_tenant_id`), atomic transactional outbox persistence (`write_outbox`), and background relay publishing (`relay_outbox`) with in-memory fallback when Postgres is unavailable.
  - Added `trip_store` worker and database helpers (`upsert_trip_result`, `record_trip_event`, `record_llm_usage`, `get_trip_by_id`) to persist finalized trip results, domain events, and token usage metrics.
- **CloudEvents v1.0 Envelopes, Structured Cache Keys & Single-Flight Locking (`services/common/schemas.py`, `services/*/provider.py`)**:
  - Added strict CloudEvents v1.0 schema validation and structured tenant-scoped cache keys with Redis single-flight locking to prevent duplicate concurrent provider/MCP lookups.
- **Synthesis Barrier State Machine, Timeout Janitor & Single-Call Synthesis (`services/synthesis_service/barrier.py`, `services/synthesis_service/worker.py`, `services/synthesis_service/synthesizer.py`)**:
  - Implemented `BarrierStateMachine` with a background `janitor_loop` scanning for expired scatter-gather barriers every second to trigger partial synthesis on timeout, paired with single-call LLM itinerary synthesis.
- **Dead Letter Queue (DLQ) Replay Tooling & Gateway Endpoint (`tools/dlq_replay.py`, `services/bff_gateway/main.py`)**:
  - Added standalone CLI DLQ replay utility (`tools/dlq_replay.py`) and admin replay endpoint in `bff_gateway` to re-publish failed messages from `stream:travel:dlq` back to their original streams.
- **Phase 3 Integration & Async Test Suite (`tests/test_phase3_features.py`, `pyproject.toml`, `uv.lock`, `requirements.txt`)**:
  - Added async Phase 3 test suite covering CloudEvents v1.0 schemas, outbox write/relay, barrier state machine and janitor expiration, single-call synthesis, structured cache keys with single-flight locking, and `trip_store` upsert/retrieval.
  - Added `test` optional dependency group (`pytest>=8.4.0`, `pytest-asyncio>=1.5.0`) in `pyproject.toml`, updated `uv.lock`, and exported pinned runtime dependencies to `requirements.txt`.

### Fixed
- **Linting, Regex Escape Sequences & Exception Handling (`services/bff_gateway/main.py`, `services/common/db.py`, `services/flight_service/provider.py`, `services/synthesis_service/worker.py`, `tools/dlq_replay.py`)**:
  - Fixed unescaped backspace literals in flight/airport regexes (`\b([A-Z]{2,3}\d{1,4})\b`, `\b([A-Z]{3})\b`), imported missing `Any` annotations, combined nested `async with` context managers (`SIM117`), and narrowed broad `except Exception:` blocks to explicit exception tuples so `ruff check .` passes cleanly.



## [1.5.0] - 2026-11-20

### Added
- **Identity & OIDC Hardening (`services/auth_service/main.py`, `services/auth_service/security.py`, `services/auth_service/models.py`)**:
  - Added Google OIDC authorization URL generation with CSRF `state`, `nonce`, and PKCE (`S256` code challenge / `code_verifier`) persisted with TTL, paired with `id_token` JWT signature/claim/nonce/email-verification checks.
  - Added UUIDv5-based deterministic user IDs (`generate_user_id`), Argon2id password hashing/verification (`hash_password`, `verify_password`), refresh token issuance, and Redis-backed `jti` token revocation (`POST /api/v1/auth/revoke`).
- **Key Management, JWKS & Token Lifecycle (`services/auth_service/security.py`, `services/common/auth_middleware.py`)**:
  - Derived `kid` from RFC 7638 JWK thumbprints (`compute_rfc7638_kid`) and supported primary + previous key rotation overlap in `get_jwks()`.
  - Offloaded JWKS signing-key lookup off the async event loop via `asyncio.to_thread(...)`, checked token revocation in `get_current_user`, and added explicit `require_any_role` and `require_all_roles` RBAC helpers.
- **BFF Gateway, Tenancy, Sessions & Trip Ownership (`services/bff_gateway/main.py`, `services/bff_gateway/session_manager.py`)**:
  - Enforced `SessionManager.validate_request` (session + `X-CSRF-Token`) on `POST /api/v1/trips/plan` and `GET /api/v1/trips/{correlation_id}/stream`, added per-user/tenant/IP sliding-window rate limiting, added `Idempotency-Key` response caching, bound `trip:ownership:{tenant_id}:{correlation_id}` records in Redis, and used full 128-bit UUIDs (`trip_<uuid4().hex>`).
  - Propagated `tenant_id` across session keys (`session:{tenant_id}:{session_id}`), rate-limit keys, provider cache keys, and `PlanningInitiatedPayload`.
- **Kubernetes Infrastructure, Isolation & Security Hardening (`k8s/namespace.yaml`, `k8s/network-policies.yaml`, `k8s/postgres.yaml`, `k8s/redis.yaml`, `k8s/auth-service.yaml`, `k8s/bff-gateway.yaml`, `k8s/domain-workers.yaml`)**:
  - Added `k8s/postgres.yaml`, `k8s/redis.yaml`, and `k8s/network-policies.yaml` (default-deny ingress/egress plus least-privilege service/egress policies), and applied Pod Security Admission `restricted` labels in `k8s/namespace.yaml` along with non-root `securityContext` and digest-pinned container images.
- **LLM, MCP & Stream Privacy Hardening (`services/common/pii_redactor.py`, `services/synthesis_service/synthesizer.py`, `services/synthesis_service/worker.py`, `services/flight_service/provider.py`, `services/hotel_service/provider.py`, `services/weather_service/provider.py`)**:
  - Redacted PII (`redact_pii`), stripped links/HTML, truncated inputs, and wrapped untrusted user queries and flight/hotel/weather tool outputs in XML delimiters in `SynthesisEngine`, replacing shared mutable `last_result` state with a `contextvars.ContextVar`.
  - Enforced `asyncio.timeout(...)` on MCP calls, strict tool allowlists without arbitrary `tools[0]` fallbacks, and scoped environment variables passed to MCP subprocesses.

### Changed
- **Session Lifecycle & Auth Endpoints (`services/bff_gateway/main.py`, `services/bff_gateway/session_manager.py`, `services/auth_service/main.py`)**:
  - Rotated sessions on login, enforced session absolute TTLs and `Secure` cookie flags in production, and removed unauthenticated guest session minting on `GET /api/v1/auth/me`.
  - Gated direct password login on `ENVIRONMENT != "production"` and failed closed on missing/invalid Google OIDC configuration or state/nonce/token validation.
- **Redis Eviction & Container Runtime (`docker-compose.yml`, `k8s/redis.yaml`, `services/Dockerfile.worker`)**:
  - Switched Redis memory policy from `allkeys-lru` to `noeviction` with AOF persistence (`--appendonly yes`) and authentication (`--requirepass`) in `docker-compose.yml` and `k8s/redis.yaml`, and set `UV_PYTHON_DOWNLOADS=never` with pinned MCP tool versions in `services/Dockerfile.worker`.

### Fixed
- **Lint & Exception Handling (`services/auth_service/main.py`, `services/bff_gateway/main.py`, `services/common/auth_middleware.py`, `services/common/event_bus.py`, `services/flight_service/provider.py`, `services/hotel_service/provider.py`, `services/synthesis_service/synthesizer.py`, `services/weather_service/provider.py`)**:
  - Imported missing `time` module in `services/auth_service/main.py` and narrowed broad `except Exception:` handlers to specific exception tuples to pass `ruff check .`.


## [1.4.0] - 2026-11-19

### Added
- **OpenWeather MCP Server Integration (`services/weather_service/provider.py`)**:
  - Integrated the `openweather-mcp` (`==0.1.0`) server using `MultiServerMCPClient` (`langchain-mcp-adapters`) and normalized weather output payloads consistent with `services/hotel_service/provider.py`.
  - Preserved Redis caching (`weather:cache:...`), `CircuitBreaker` protection, and `_fallback_weather` fallback handling when MCP invocation fails or `OPENWEATHER_API_KEY` is missing.
- **AviationStack MCP Server Integration (`services/flight_service/provider.py`)**:
  - Integrated the AviationStack MCP server (`https://github.com/Pradumnasaraf/aviationstack-mcp.git`) with dynamic tool/schema resolution and normalized flight output payloads.
  - Preserved Redis caching (`flight:cache:...`), `CircuitBreaker` protection, and `_fallback_flights` fallback handling on MCP server failure, timeout, or missing `AVIATIONSTACK_API_KEY`.
- **DuckDuckGo MCP Server Integration & 3-Tier Hotel Search Resilience (`services/hotel_service/provider.py`)**:
  - Integrated the **DuckDuckGo Model Context Protocol (MCP) server** via `MultiServerMCPClient` (`langchain-mcp-adapters`) over `stdio` transport (`uvx duckduckgo-mcp`) as an automated secondary fallback tier for accommodation discovery.
  - Implemented a 3-tier resilient failover pipeline (`_execute_tiered_search`) routing requests sequentially through **Tier 1 (Tavily Search API)** -> **Tier 2 (DuckDuckGo MCP Server)** -> **Tier 3 (Static Heuristic Recommendations)** while preserving 12-hour Redis caching (`hotel:cache:<hash>`).
  - Added independent stateful `CircuitBreaker` isolation (`TavilyHotelBreaker` and `DuckDuckGoMCPBreaker`) to prevent cascading latency and ensure uninterrupted Scatter-Gather barrier completion in `synthesis_service`.
- **Explicit `ProviderResult` & Honest Degradation Tracking (`services/common/schemas.py`, `services/flight_service/`, `services/hotel_service/`, `services/weather_service/`, `services/synthesis_service/synthesizer.py`)**:
  - Added `ProviderResult(text, source, degraded)` and propagated `source` and `degraded` flags through provider outputs, worker payloads, and synthesis prompts so degraded/fallback responses are surfaced honestly and instructed to state `"data unavailable"` rather than fabricating figures.
- **Event Bus Resilience, DLQ & Atomic Synthesis Barrier (`services/common/event_bus.py`, `services/synthesis_service/worker.py`, `services/*/worker.py`)**:
  - Added Pending Entries List (PEL) recovery (`XPENDING` / `XAUTOCLAIM`), delivery attempt tracking, Dead Letter Queue (DLQ) routing for poison messages, `MAXLEN` stream trimming, and unique pod/host-based consumer group names.
  - Made `check_and_synthesize` atomic to prevent TOCTOU duplicate synthesis across replicas and required `user_query` before synthesizing.
- **CI Entrypoint Smoke Test, Lockfile & Hardened CI/Release Pipelines (`tests/test_entrypoints.py`, `uv.lock`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`)**:
  - Added an entrypoint smoke test importing service and worker modules, generated `uv.lock` for deterministic builds, updated `.github/workflows/ci.yml` to export and install locked runtime dependencies (`uv export --frozen --no-dev --no-hashes` + `uv pip install --system --no-deps`) before running `pytest`, and expanded CI with `ruff`, `mypy`, `pytest`, Docker image builds, and Trivy vulnerability scanning.

### Changed
- **Dependencies, Container Builds & Deployment Manifests (`pyproject.toml`, `services/Dockerfile.worker`, `services/Dockerfile.gateway`, `docker-compose.yml`, `k8s/configmap.yaml`, `k8s/domain-workers.yaml`)**:
  - Added `openweather-mcp==0.1.0` and AviationStack MCP server dependency/tooling support in `pyproject.toml`.
  - Updated the multi-stage worker Docker build (`services/Dockerfile.worker`) to copy `uv` and `uvx` binaries into the runtime image alongside `git` and `curl` and pre-install/configure `openweather-mcp` and `aviationstack-mcp` alongside `duckduckgo-mcp` under the non-root `app` user (`UV_TOOL_DIR=/home/app/.local/share/uv/tools`).
  - Propagated MCP server configuration and API key environment variables (`OPENWEATHER_API_KEY`, `AVIATIONSTACK_API_KEY`, `UV_CACHE_DIR`, `UV_TOOL_DIR`) across `docker-compose.yml`, `k8s/configmap.yaml`, and `k8s/domain-workers.yaml`.
  - Scaled `hotel-service` pod resource requests (`200m` CPU / `256Mi` memory) and limits (`800m` CPU / `512Mi` memory) and aligned worker pod resource/environment settings in `k8s/domain-workers.yaml` for MCP subprocess execution while maintaining W3C `traceparent` propagation and CloudEvents compatibility.
  - Migrated `MultiServerMCPClient` usage to async `get_tools()` with `asyncio.timeout(...)`, long-lived worker sessions with shutdown cleanup, direct binary invocation, and explicit tool allowlists.
  - Passed structured trip fields (`destination`, `departure_city`, dates) into workers/providers, removed the regex `extract_city` heuristic, and moved synchronous Tavily calls off the event loop via `asyncio.to_thread(...)`.
  - Rebuilt the frontend client (`frontend/static/js/app.js`, `frontend/templates/index.html`, `frontend/static/css/styles.css`) onto the BFF contract (`/api/v1/auth/me` for CSRF, `POST /api/v1/trips/plan` with `X-CSRF-Token`, and `EventSource` on `/api/v1/trips/{id}/stream`), removing the `/api/config` session-key UI and simulated progress timer.
  - Hardened auth and runtime configs: removed `"admin"` email privilege escalation in `direct_login`, gated `/api/v1/auth/login` and Google mock fallback on `ENVIRONMENT != "production"`, passed Gemini API keys via `x-goog-api-key` instead of query params, added `--forwarded-allow-ips` to gateway Uvicorn, unpublished internal Redis/Postgres/Auth ports in `docker-compose.yml`, removed placeholder `Secret` entries from `k8s/configmap.yaml`, and fixed release archive packaging in `.github/workflows/release.yml`.

### Fixed
- **Linting, Formatting & Exception Handling (`services/`)**:
  - Resolved Ruff linting and formatting issues across `services/` (narrowing blind `Exception` catches under `BLE001`, cleaning up `try`/`except`/`pass` blocks under `S110`, simplifying nested `if` statements under `SIM102`, refactoring FastAPI `Depends` defaults under `B008`, fixing undefined name imports under `F821`, and cleaning up `logger.exception` usage under `G201`/`TRY401`/`G202`) and applied `ruff format .`.
- **Cache Discipline & Output Formatting (`services/flight_service/provider.py`, `services/hotel_service/provider.py`, `services/weather_service/provider.py`)**:
  - Prevented degraded fallback results from being cached with long TTLs (skipping or limiting negative cache TTL to `<= 60s`).
  - Fixed hotel fallback text formatting and joined list/snippet outputs with proper newlines (`"\n".join(...)`) instead of `"".join(...)`.
  
## [1.3.0] - 2026-11-18

### Added
- **Enterprise Distributed Microservices Architecture**:
  - **API Gateway & Backend-For-Frontend (BFF) Service (`services/bff_gateway/`)**:
    - Decoupled client ingress with secure, encrypted HTTP-only session cookies (`tb_session_id`) and Anti-CSRF token verification (`X-CSRF-Token`), eliminating raw JWT storage in browser `localStorage`.
    - Distributed sliding-window rate limiting backed by Redis.
    - Asynchronous Server-Sent Events (SSE) streaming endpoint (`/api/v1/trips/{correlation_id}/stream`) providing live progress updates and final synthesized itineraries directly to clients.
  - **Centralized Auth & Identity Service (`services/auth_service/`)**:
    - Offloaded identity verification to external OIDC providers (Google Auth / OIDC) with state/PKCE security.
    - Centralized RS256 asymmetric JWT signing and issuance with user identity, roles, and tenant metadata.
    - Public RFC 7517 JWKS provider endpoint (`/.well-known/jwks.json`) for downstream key distribution.
  - **Stateless Microservice Verification Middleware (`services/common/auth_middleware.py`)**:
    - High-performance, zero-database verification middleware utilizing thread-safe in-memory caching of JWKS public keys.
    - Role-Based Access Control (RBAC) dependency guards (`require_roles`).
  - **Asynchronous Event Backbone & CloudEvents (`services/common/event_bus.py`, `services/common/schemas.py`)**:
    - Event-driven choreography using Redis Streams with consumer groups (`XGROUP`, `XREADGROUP`, `XACK`) replacing in-process LangGraph state graph bottlenecks.
    - Full CloudEvents v1.0 specification compliance across all domain event envelopes (`travel.planning.initiated`, `travel.flights.completed`, `travel.hotels.completed`, `travel.weather.completed`, `travel.synthesis.completed`).
    - W3C Distributed TraceContext propagation (`traceparent`) across microservice boundaries (`services/common/telemetry.py`).
  - **Scatter-Gather Parallel Domain Microservices**:
    - **Flight Agent Service (`services/flight_service/`)**: Concurrent AviationStack integration, route analysis, and Redis caching.
    - **Hotel Agent Service (`services/hotel_service/`)**: Concurrent Tavily web search integration and accommodation caching.
    - **Weather Agent Service (`services/weather_service/`)**: Concurrent OpenWeather API integration and destination geocoding.
    - Reduced end-to-end multi-agent research latency by ~60% through concurrent scatter-gather execution.
  - **Itinerary & Synthesis Service (`services/synthesis_service/`)**:
    - Atomic Redis barrier aggregator collecting asynchronous agent outputs for each trip correlation ID.
    - Multi-agent Groq / Gemini LLM prompt orchestration for day-by-day scheduling and executive travel plan synthesis.
  - **Resilient Multi-Provider LLM Architecture with 3-Tier Fallback Chain (`services/common/llm_provider.py`, `services/common/resilient_chain.py`)**:
    - **Standardized Base Contract (`BaseLLMProvider`)**: Abstract interface enforcing asynchronous `generate()` and `generate_structured()` methods returning standardized `LLMResult` with token counts, latency measurement, and structured JSON output.
    - **Concrete Provider Adapters**:
      - `GroqLLMProvider`: Tier 1 primary cloud provider running `llama-3.3-70b-versatile` with response metadata token accounting.
      - `GeminiLLMProvider`: Tier 2 primary cloud fallback utilizing Google Gemini REST API (`gemini-2.5-flash` / `gemini-1.5-pro`) with native `responseSchema` / `responseMimeType="application/json"` enforcement and `usageMetadata` tracking.
      - `LocalHuggingFaceProvider`: Tier 3 air-gapped consumer-hardware fallback strictly constrained to <12GB VRAM (`Qwen/Qwen2.5-7B-Instruct` or `HuggingFaceTB/SmolLM2-1.7B-Instruct`), supporting local OpenAI-compatible endpoints (Ollama / llama.cpp), 4-bit/8-bit quantized Hugging Face pipelines, and deterministic offline generation.
    - **Resilient Fallback Chain Orchestrator (`ResilientLLMChain`)**: Strict priority failover (Groq -> Google Gemini -> Local Hugging Face <12GB VRAM) guarded by dedicated circuit breakers (`CircuitBreaker`) and automatic retry handling.
    - **OpenTelemetry Observability & Metrics**: Top-level `llm.request` spans and child `llm.provider.<name>` spans capturing `llm.provider`, `llm.model`, `llm.tier_priority`, `llm.latency_ms`, and `llm.tokens.prompt`/`llm.tokens.completion`/`llm.tokens.total`.
    - **Synthesis Service Integration (`services/synthesis_service/synthesizer.py`)**: Refactored `SynthesisEngine` to eliminate direct single-vendor coupling, delegating itinerary creation and markdown formatting to `ResilientLLMChain`.
    - **Project Dependencies (`pyproject.toml`)**: Declared core dependencies and added modular optional dependency groups (`local-llm`, `google`, `all`).
  - **Reliability, Resilience & Fault Tolerance (`services/common/resilience.py`)**:
    - Implemented stateful Circuit Breakers (`CLOSED`, `OPEN`, `HALF_OPEN`) with exponential backoff retries and randomized jitter.
    - Graceful multi-tiered fallback handlers for all external vendors (AviationStack, Tavily, OpenWeather, Groq).
  - **Production Containerization & Kubernetes Manifests**:
    - Multi-stage, non-root Dockerfiles (`services/Dockerfile.gateway`, `services/Dockerfile.auth`, `services/Dockerfile.worker`).
    - Updated `docker-compose.yml` orchestrating all microservices, Redis 7 (broker + cache), and PostgreSQL 16.
    - Production Kubernetes manifests in `k8s/` including Deployments, ClusterIP Services, Horizontal Pod Autoscalers (HPA), Ingress with TLS, ConfigMaps, and Secrets.

### Fixed
- **Event Loop Concurrency (`app.py`)**: Offloaded synchronous `run_travel_agent` execution to Starlette's threadpool (`run_in_threadpool`) inside the `/api/travel` POST route, preventing 30–90 second blocking LLM and MCP tool executions from starving the main FastAPI asyncio event loop.

## [1.2.0] - 2026-11-13

### Added
- **Centralized Prompt Registry (`src/agents/prompts_registry.py`)**: Introduced `PromptRegistry` to manage, version, format, and override all system prompts, user query templates, and output guidelines while purging inline prompt strings from agent node definitions (retaining re-export compatibility in `src/agents/prompts.py`).
- **Dynamic Graph Routing Engine (`src/graph/graph.py`)**: Added `build_dynamic_graph()` to construct LangGraph execution workflows dynamically from ordered node configuration lists or custom node dictionaries instead of rigid sequential edges.
- **Standardized Provider & Telemetry Interfaces (`src/clients/llm_provider.py`, `src/utils/telemetry.py`)**:
  - Created `BaseLLMProvider` and concrete `GroqLLMProvider` to isolate vendor-agnostic model invocation, caching, and credential resolution.
  - Implemented unified `track_performance` decorator supporting sync/async functions to automatically track execution time, log lifecycle events, handle exceptions, and record metrics into an in-memory `TelemetryCollector`.

### Changed
- **Decoupled Agent & Tool Protocols (`src/agents/base.py`, `src/mcp_servers/registry.py`)**:
  - Standardized execution signatures across all workflow agents (`FlightAgent`, `HotelAgent`, `WeatherAgent`, `ItineraryAgent`, `FinalAgent`) using a PEP 544 runtime-checkable `AgentProtocol` and abstract `BaseAgent` class.
  - Built a centralized `ToolRegistry` and adapter pattern to decouple MCP tool execution mechanics (AviationStack, OpenWeather, Tavily) from individual agent implementations.

### Deliverables
- Bundled all modified agent nodes, MCP server registries, client abstraction modules, telemetry utilities, graph builders, and configuration templates into `refactored_travelplanner_architecture.zip`.


## [1.1.0] - 2026-11-12

### Changed
- **Production-Grade Configuration Architecture**: Migrated system configuration to modular, nested Pydantic v2 sub-configs (`AppConfig`, `SecurityConfig`, `DatabaseConfig`, `RedisConfig`, `LLMConfig`, `ExternalAPIsConfig`, and `TruncationConfig`) using `BaseSettings` and `SettingsConfigDict`.
- **Robust Environment Mapping**: Integrated `AliasChoices` and nested double-underscore delimiters (`__`) to support backward compatibility with flat environment variables alongside typed nested structures.
- **Secure Secret Handling**: Refactored LLM and external API clients to consume `SecretStr`-protected keys safely from the central configuration model.
- **Application & Module Refactoring**: Fully updated `src/api`, `src/clients`, `src/agents`, `src/mcp_servers`, and `app.py` to utilize structured configuration parameters, secure session cookies, and strict CORS policies.
- **Codebase Snapshot Tools**: Added custom exclusion patterns to `repomix.config.json` for enhanced code packing and filtering.


## [1.0.0] - 2026-11-11

### Added
- **Multi-Agent Orchestration Engine**: Built with LangGraph, routing trip requests sequentially through destination extraction, flight, hotel, weather, itinerary generation, and final summary agents.
- **MCP (Model Context Protocol) Integration Layer**:
  - Remote MCP server integration with **Tavily** for live accommodation and web search.
  - Local stdio MCP integration with **AviationStack** for airport and airline data lookups.
  - Custom local stdio MCP weather server (`weather_server.py`) powered by **OpenWeather API**.
- **FastAPI Web Server & UI**:
  - Web interface with dark/light themes, prompt suggestions, and an interactive Trip Builder tool.
  - Endpoints for executing travel planning runs (`/api/travel`), server health checks (`/health`), and dynamic credential configuration (`/api/config`).
- **Session & Security System**:
  - In-memory per-session API credential override store (`src/api/sessions.py`) allowing users to enter custom Groq API keys and Database URLs without disk persistence.
  - Real-time pre-flight liveness checking for Groq API keys and PostgreSQL connection strings (`src/api/validation.py`).
- **Persistence & Caching**:
  - LangGraph PostgreSQL state checkpointer using `psycopg` to preserve multi-turn conversation threads.
  - Optional Redis caching layer (`src/clients/cache.py`) for expensive tool calls (airlines, airports, destination extractions, weather, and Tavily queries) with automatic fallback and self-healing reconnection logic.
- **Containerization & Deployment Support**:
  - Production-ready `Dockerfile` multi-stage build running under non-root execution (`app` user) with pre-installed `aviationstack-mcp`.
  - `docker-compose.yml` supporting optional local PostgreSQL (`local-db` profile) and Redis cache services.
  - Vercel deployment configuration (`vercel.json`) and frontend asset build script (`scripts/build-frontend.sh`).

[1.7.1]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/releases/tag/v1.0.0