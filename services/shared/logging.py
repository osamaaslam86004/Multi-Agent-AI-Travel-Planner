"""
Structured Logging Utilities.
"""
from services.common.telemetry import configure_structured_logging


def setup_logging():
    configure_structured_logging()