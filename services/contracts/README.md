# TravelBrain Internal Service Contracts & Schema Compatibility Rules

## 1. Domain vs. Transport Schema Separation
- **Transport Schemas** (`services/contracts/v1/`, `services/contracts/v2/`): Exposed at REST/HTTP API boundaries for clients.
- **Domain Payloads** (`services/contracts/events.py`): Used internally by microservices, workers, and event bus handlers.

## 2. API Response Envelopes
All REST endpoints return standard `ApiResponse[T]` envelopes.

## 3. Event Versioning Rules
All CloudEvents wrap data payloads using `CloudEventV1` with explicit event_version metadata (1.0.0).