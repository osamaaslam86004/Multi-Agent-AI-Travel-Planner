# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/osamaaslam86004/Multi-Agent-AI-Travel-Planner/releases/tag/v1.0.0