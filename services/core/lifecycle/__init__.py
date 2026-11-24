"""
Service Lifecycle Standardization Package.
"""
from services.core.lifecycle.manager import WorkerLifespan, lifespan_manager
from services.core.lifecycle.teardown import (
    ServiceTeardownRegistry,
    get_teardown_registry,
)

__all__ = [
    "ServiceTeardownRegistry",
    "WorkerLifespan",
    "get_teardown_registry",
    "lifespan_manager",
]