
<h1 align="center">TravelBrain AI</h1>

<p align="center">
  <img src="https://img.shields.io/badge/architecture-microservices-blue.svg" alt="Architecture">
  <img src="https://img.shields.io/badge/status-production--ready-success.svg" alt="Status">
  <a href="https://github.com/KalyanM45/TravelBrain-Multi-Agent-AI-Travel-Planner/issues"><img src="https://img.shields.io/github/issues/KalyanM45/TravelBrain-Multi-Agent-AI-Travel-Planner.svg" alt="GitHub Issues"></a>
  <a href="https://github.com/KalyanM45/TravelBrain-Multi-Agent-AI-Travel-Planner/pulls"><img src="https://img.shields.io/github/issues-pr/KalyanM45/TravelBrain-Multi-Agent-AI-Travel-Planner.svg" alt="GitHub Pull Requests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue.svg" alt="License"></a>
</p>

---

<p align="center"> An enterprise-grade, distributed multi-agent AI travel planning platform. Describe the trip you want in
    plain English and get back flights, hotels, weather, and a synthesized day-by-day itinerary — researched concurrently across independent microservices in seconds.
    <br>
</p>

## 📝 Table of Contents

- [About](#about)
- [Enterprise Architecture](#architecture)
  - [High-Level Topology](#high-level-topology)
  - [Core Architectural Pillars](#core-architectural-pillars)
- [Getting Started](#getting_started)
  - [Prerequisites](#prerequisites)
  - [Option 1: Microservices Deployment (Docker Compose)](#option-1-microservices-deployment-docker-compose)
  - [Option 2: Kubernetes Deployment (Production)](#option-2-kubernetes-deployment-production)
  - [Option 3: Local Monolith Development](#option-3-local-monolith-development)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgement)

---

## 🧐 About <a name = "about"></a>

Planning a trip usually means juggling half a dozen browser tabs — one for flights, another for hotels, a third for weather, and a notes app where you try to fit it all into a sensible order. **TravelBrain AI** collapses that into a single conversation. You describe the trip you want in your own words — *"Plan a 10 day Europe trip from India in April, mid-range budget"* — and an armada of AI domain specialists researches it in parallel.

| Specialist | Domain Intelligence | Upstream Provider |
|---|---|---|
| ✈️ **Flight Agent** | Route analysis, departure/arrival airports, airlines, fare estimates | AviationStack MCP / API |
| 🏨 **Hotel Agent** | Accommodation options matched to destination, budget, and neighborhood | Tavily MCP / Search API |
| 🌤️ **Weather Agent** | Geocoding, real-time conditions, and 5-day predictive forecasts | OpenWeatherMap API |
| 🗺️ **Synthesis Agent** | Day-by-day scheduling, budget breakdown, and executive travel plan | Groq (Llama 3.3) -> Gemini 2.5/1.5 -> Local Hugging Face (<12GB VRAM) |

---

## 🏛️ Enterprise Architecture <a name = "architecture"></a>

TravelBrain AI has evolved from a single-process modular monolith into a production-ready, highly available **Event-Driven Microservices Architecture** operating under the **Scatter-Gather Saga Pattern**.

### High-Level Topology

flowchart TD
    Client["Browser / Mobile Client"] -->|"HTTPS + Encrypted HttpOnly Cookie"| BFF["API Gateway / BFF Service\n(:8000)"]
    
    subgraph IAM["Enterprise IAM Boundary"]
        AuthSvc["Auth & Identity Service\n(:8001)"]
        GoogleOIDC["Google Identity / OIDC Provider"]
    end
    
    BFF <-->|"OAuth2 Token Exchange"| AuthSvc
    AuthSvc <-->|"Federated Login"| GoogleOIDC
    BFF -.->|"Stateless Signature Verification via Cached JWKS"| AuthSvc

    subgraph Broker["Event Backbone (Redis Streams & PubSub)"]
        StreamInit["stream:travel:planning:initiated"]
        StreamFlights["stream:travel:flights:completed"]
        StreamHotels["stream:travel:hotels:completed"]
        StreamWeather["stream:travel:weather:completed"]
        StreamFinal["stream:travel:synthesis:completed"]
    end

    subgraph Workers["Stateless Concurrent Domain Workers"]
        FlightWorker["Flight Agent Worker\n(AviationStack + Cache)"]
        HotelWorker["Hotel Agent Worker\n(Tavily + Cache)"]
        WeatherWorker["Weather Agent Worker\n(OpenWeather + Cache)"]
        SynthesisWorker["Synthesis Worker\n(Scatter-Gather Barrier + LLM)"]
    end

    %% Flow
    BFF -->|"Publishes CloudEvent"| StreamInit
    StreamInit --> FlightWorker
    StreamInit --> HotelWorker
    StreamInit --> WeatherWorker

    FlightWorker --> StreamFlights
    HotelWorker --> StreamHotels
    WeatherWorker --> StreamWeather

    StreamFlights --> SynthesisWorker
    StreamHotels --> SynthesisWorker
    StreamWeather --> SynthesisWorker

    SynthesisWorker --> StreamFinal
    SynthesisWorker -->|"Real-Time Progress / Final Payload"| RedisPubSub["Redis PubSub Channel\ntrip:stream:[id]"]
    RedisPubSub -->|"Server-Sent Events (SSE)"| BFF
    BFF -->|"Live Markdown & JSON Stream"| Client

### Core Architectural Pillars

1. **Horizontal Scalability & Scatter-Gather Parallelization**:
   - Agent coordination is decoupled from in-process LangGraph locks using **Redis Streams** with consumer groups (`XGROUP`, `XREADGROUP`, `XACK`).
   - Flight, Hotel, and Weather agents execute **concurrently**, cutting overall trip planning latency by ~60%.
   - Ingress and worker nodes are stateless, supporting dynamic autoscaling via Kubernetes HPA.

2. **Enterprise Authentication & Authorization (Google OIDC + JWT Hybrid Pattern)**:
   - **Identity Offloading**: Google OIDC handles login and MFA without storing passwords in local databases.
   - **Cryptographic Token Issuance**: The centralized Auth Service issues RS256 asymmetric JSON Web Tokens containing user claims, roles, and tenant metadata.
   - **Stateless Verification (JWKS)**: Downstream services locally verify incoming `Authorization: Bearer <JWT>` signatures using public keys cached in-memory from `/.well-known/jwks.json`.
   - **Browser Security**: The API Gateway (BFF) exchanges JWTs for secure, encrypted `HttpOnly; SameSite=Lax; Secure` cookies (`tb_session_id`) and injects `X-CSRF-Token` headers, preventing token theft via XSS.

3. **Reliability & Fault Tolerance**:
   - **Circuit Breakers**: Stateful breakers (`CLOSED`, `OPEN`, `HALF_OPEN`) isolate failures from external APIs (AviationStack, Tavily, OpenWeather, Groq).
   - **Exponential Backoff with Jitter**: Automatically handles transient rate-limiting and connection drops.
   - **Multi-Tiered Fallbacks**: If an external provider experiences an outage, services automatically fall back to cached data or regional climatological/heuristic averages without halting the pipeline.

4. **Distributed Observability**:
   - W3C Distributed TraceContext headers (`traceparent`) propagate across HTTP, gRPC, and Redis Stream event envelopes.

5. **Resilient Multi-Provider LLM Fallback Chain (Groq -> Gemini -> Local <12GB VRAM)**:
   - **Pluggable Provider Abstraction (`BaseLLMProvider`)**: Standardized asynchronous contract tracking latency, token usage (`prompt_tokens`, `completion_tokens`, `total_tokens`), and schema-validated structured output.
   - **3-Tier Failover Priority**:
     1. **Tier 1 (Groq)**: Cloud inference utilizing `llama-3.3-70b-versatile`.
     2. **Tier 2 (Google Gemini)**: Primary cloud fallback utilizing Gemini REST v1beta (`gemini-2.5-flash` / `gemini-1.5-pro`) with native JSON schema enforcement.
     3. **Tier 3 (Local Hugging Face Model)**: Consumer-grade, air-gapped fallback running strictly under 12GB VRAM (`Qwen/Qwen2.5-7B-Instruct` or `HuggingFaceTB/SmolLM2-1.7B-Instruct`) supporting local endpoints (Ollama / llama.cpp), 4-bit/8-bit quantized pipelines, or deterministic offline synthesis.
   - **OpenTelemetry & Circuit Breakers**: Instrumented with custom spans (`llm.request`, `llm.provider.<name>`) and protected by circuit breakers against rate limits and upstream outages.

---

## 🏁 Getting Started <a name = "getting_started"></a>

### Prerequisites

- **Docker & Docker Compose** (Recommended for Microservices deployment)
- **Python 3.11+** & **[uv](https://docs.astral.sh/uv/)** (For local monolith development)
- **API Keys** (Free tiers available):
  - [Groq](https://console.groq.com/) (Required for LLM synthesis)
  - [Tavily](https://tavily.com/) (Hotel search)
  - [AviationStack](https://aviationstack.com/) (Flights)
  - [OpenWeather](https://openweathermap.org/api) (Weather forecasts)
  - [Google Cloud Console](https://console.cloud.google.com/) (Optional: Google OIDC Client ID & Secret)

---

### Option 1: Microservices Deployment (Docker Compose)

The easiest way to run the complete distributed microservices ecosystem (BFF Gateway, Auth Service, Domain Workers, Redis Streams, and PostgreSQL) is with Docker Compose:

1. **Clone the repository**:
   git clone https://github.com/KalyanM45/TravelBrain-Multi-Agent-AI-Travel-Planner.git
   cd TravelBrain-Multi-Agent-AI-Travel-Planner

2. **Create your environment configuration**:
   cp .env.example .env
   Add your keys in `.env`:
   # LLM Providers (3-Tier Fallback Chain)
   GROQ_API_KEY=gsk_...
   GEMINI_API_KEY=AIzaSy...              # Optional: Tier 2 Cloud Fallback
   LOCAL_LLM_URL=http://localhost:11434/v1 # Optional: Tier 3 Local Endpoint (Ollama / llama.cpp)
   LOCAL_LLM_MODEL=Qwen/Qwen2.5-7B-Instruct # Optional: <12GB VRAM Model

   # External Data Integrations
   TAVILY_API_KEY=tvly-...
   AVIATIONSTACK_API_KEY=...
   OPENWEATHER_API_KEY=...

   # Enterprise Identity (Google OIDC)
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...

3. **Start the microservices stack**:
   docker compose up -d --build

4. **Verify running services**:
   docker compose ps
   - **BFF / API Gateway**: `http://localhost:8000`
   - **Auth Service & JWKS**: `http://localhost:8001/.well-known/jwks.json`
   - **Redis Streams & Cache**: `localhost:6379`
   - **PostgreSQL**: `localhost:5432`

Open **<http://localhost:8000>** in your browser to start planning trips!

---

### Option 2: Kubernetes Deployment (Production)

Production Kubernetes manifests including Deployments, Services, Horizontal Pod Autoscalers (HPA), and NGINX Ingress are located in the `k8s/` directory.

# 1. Create dedicated namespace
kubectl apply -f k8s/namespace.yaml

# 2. Apply ConfigMaps and Secrets
kubectl apply -f k8s/configmap.yaml

# 3. Deploy all microservices and Ingress
kubectl apply -f k8s/

Inspect the cluster rollout:
kubectl get pods -n travelbrain -w
kubectl get hpa -n travelbrain

---

## 🎈 Usage <a name="usage"></a>

### Planning a Trip

Type your request into the prompt bar:

> *Plan a 10 day Europe trip from India in April, mid-range budget*

> *I want a relaxed 5 day trip to Rome and Florence in September for two people*

### Real-Time Streaming & Visual Tabs

The API Gateway provides a live Server-Sent Events (SSE) feed showing the status of each specialist in real time:
- **Flights**: Airline options, estimated airfares, and duration.
- **Hotels**: Accommodation choices matching your budget.
- **Weather**: Forecast and climatological advisories.
- **Itinerary**: Day-by-day structured itinerary with activity highlights.

---

## 🤔 Troubleshooting <a name = "troubleshooting"></a>

<details>
<summary><b>Microservices: Redis or Auth connection errors in worker logs</b></summary>

Ensure the Redis and Auth containers are healthy:
docker compose ps
docker compose logs -f bff-gateway auth-service
</details>

<details>
<summary><b>An error says GROQ_API_KEY is missing or model does not exist</b></summary>

Verify your Groq API key in `.env`. You can test valid models with:
curl -s https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer $GROQ_API_KEY"
</details>

<details>
<summary><b>External API Rate Limits (AviationStack / Tavily / OpenWeather)</b></summary>

The built-in Circuit Breakers will automatically trigger fallback heuristics when external rate limits are exceeded, ensuring the travel planner completes without crashing.
</details>

---

## 🤝 Contributing <a name = "contributing"></a>

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/distributed-enhancements`)
3. Commit your changes (`git commit -m "Add distributed tracing span processors"`)
4. Push to the branch (`git push origin feature/distributed-enhancements`)
5. Open a Pull Request

---

## 🎉 Acknowledgements <a name = "acknowledgement"></a>

- [Groq](https://groq.com/) for low-latency AI inference
- [Tavily](https://tavily.com/), [AviationStack](https://aviationstack.com/), and [OpenWeather](https://openweathermap.org/) for live data
- [LangChain](https://www.langchain.com/) and [FastAPI](https://fastapi.tiangolo.com/)

---

Licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE).

