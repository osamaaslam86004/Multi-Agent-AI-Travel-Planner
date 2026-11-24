"""Itinerary & Synthesis Service REST and Health Check API."""
from fastapi import FastAPI

from services.synthesis_service.synthesizer import SynthesisEngine

app = FastAPI(title="Itinerary & Synthesis Service", version="2.0.0")
engine = SynthesisEngine()
@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "itinerary-synthesis-service"}
@app.get("/health/ready")
def readiness():
    return {"status": "READY", "llm_model": engine.model_name}