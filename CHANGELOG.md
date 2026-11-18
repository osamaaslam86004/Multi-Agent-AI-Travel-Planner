# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Production-Grade Configuration Architecture**: Migrated system configuration to modular, nested Pydantic v2 sub-configs (`AppConfig`, `SecurityConfig`, `DatabaseConfig`, `RedisConfig`, `LLMConfig`, `ExternalAPIsConfig`, and `TruncationConfig`) using `BaseSettings` and `SettingsConfigDict`[cite: 2].
- **Robust Environment Mapping**: Integrated `AliasChoices` and nested double-underscore delimiters (`__`) to support backward compatibility with flat environment variables alongside typed nested structures.
- **Secure Secret Handling**: Refactored LLM and external API clients to consume `SecretStr`-protected keys safely from the central configuration model[cite: 2].
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