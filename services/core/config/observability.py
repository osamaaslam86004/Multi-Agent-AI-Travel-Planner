"""
Observability & Telemetry Domain Settings.
"""

from services.core.config.base import BaseDomainSettings


class ObservabilitySettings(BaseDomainSettings):
    service_name: str = "travelbrain-service"
    otel_exporter_otlp_endpoint: str | None = "http://localhost:4317"
    trace_sample_rate: float = 1.0
    log_level: str = "INFO"
    log_format: str = "json"
    prometheus_metrics_enabled: bool = True

    @classmethod
    def load(cls) -> "ObservabilitySettings":
        aliases = {
            "service_name": "SERVICE_NAME",
            "otel_exporter_otlp_endpoint": "OTEL_EXPORTER_OTLP_ENDPOINT",
            "log_level": "LOG_LEVEL",
        }
        return cls.load_from_env(prefix="OTEL", aliases=aliases)
