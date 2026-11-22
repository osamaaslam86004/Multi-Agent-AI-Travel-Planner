"""
Deployment & Infrastructure Domain Settings.
"""

from services.core.config.base import BaseDomainSettings


class DeploymentSettings(BaseDomainSettings):
    pod_name: str | None = None
    node_name: str | None = None
    hostname: str | None = None
    deployment_zone: str = "us-central1-a"
    region: str = "us-central1"
    keda_enabled: bool = True

    @classmethod
    def load(cls) -> "DeploymentSettings":
        aliases = {
            "pod_name": "POD_NAME",
            "node_name": "NODE_NAME",
            "hostname": "HOSTNAME",
        }
        return cls.load_from_env(prefix="DEPLOYMENT", aliases=aliases)
