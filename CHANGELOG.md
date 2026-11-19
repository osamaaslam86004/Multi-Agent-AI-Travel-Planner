# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.4.0] - 2026-11-19

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
- **CI Entrypoint Smoke Test & Hardened CI/Release Pipelines (`tests/test_entrypoints.py`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`)**:
  - Added an entrypoint smoke test importing service and worker modules, and expanded CI with `ruff`, `mypy`, `pytest`, Docker image builds, and Trivy vulnerability scanning.

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

[1.3.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/releases/tag/v1.0.0