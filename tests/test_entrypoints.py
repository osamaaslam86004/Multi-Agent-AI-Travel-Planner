"""
CI Entrypoint Smoke Test.
Verifies that every service entrypoint module (APIs, workers, auth, gateway) can be imported
without syntax errors or import regressions.
"""
import importlib

import pytest

SERVICE_ENTRYPOINTS = [
    "services.auth_service.main",
    "services.auth_service.security",
    "services.auth_service.models",
    "services.bff_gateway.main",
    "services.bff_gateway.session_manager",
    "services.flight_service.api",
    "services.flight_service.worker",
    "services.flight_service.provider",
    "services.hotel_service.api",
    "services.hotel_service.worker",
    "services.hotel_service.provider",
    "services.weather_service.api",
    "services.weather_service.worker",
    "services.weather_service.provider",
    "services.synthesis_service.api",
    "services.synthesis_service.worker",
    "services.synthesis_service.synthesizer",
    "services.synthesis_service.barrier",
    "services.trip_store.worker",
    "services.common.db",
    "tools.dlq_replay",
]
@pytest.mark.parametrize("module_name", SERVICE_ENTRYPOINTS)
def test_entrypoint_import(module_name: str) -> None:
    """Smoke test importing each service entrypoint."""
    module = importlib.import_module(module_name)
    assert module is not None, f"Failed to import entrypoint module: {module_name}"