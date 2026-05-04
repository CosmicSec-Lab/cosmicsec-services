"""
Service Discovery Manager
Handles dynamic service URL resolution based on deployment environment.
Automatically uses Docker service names in containers and localhost in local dev.
"""

import logging
import os

from cosmicsec_platform.config import get_config

logger = logging.getLogger(__name__)


class ServiceRegistry:
    """
    Registry of all CosmicSec microservices with environment-aware URL resolution.

    In Docker/Compose: Uses service names (api-gateway, auth-service, etc)
    In local dev: Uses localhost:PORT
    In self-hosted: Uses configured hostnames/IPs
    """

    # Service definitions: name -> port
    SERVICES = {
        "api_gateway": {"port": 8000, "name": "api-gateway"},
        "auth": {"port": 8001, "name": "auth-service"},
        "scan": {"port": 8002, "name": "scan-service"},
        "ai": {"port": 8003, "name": "ai-service"},
        "recon": {"port": 8004, "name": "recon-service"},
        "report": {"port": 8005, "name": "report-service"},
        "collab": {"port": 8006, "name": "collab-service"},
        "plugins": {"port": 8007, "name": "plugin-registry"},
        "integration": {"port": 8008, "name": "integration-service"},
        "bugbounty": {"port": 8009, "name": "bugbounty-service"},
        "phase5": {"port": 8010, "name": "phase5-service"},
        "agent_relay": {"port": 8011, "name": "agent-relay"},
        "notification": {"port": 8012, "name": "notification-service"},
        "compliance": {"port": 8013, "name": "compliance-service"},
        "org": {"port": 8014, "name": "org-service"},
        "admin": {"port": 8015, "name": "admin-service"},
        "egress": {"port": 8016, "name": "egress-service"},
    }

    def __init__(self):
        """Initialize the service registry."""
        self._config = get_config()
        self._url_cache: dict[str, str] = {}
        self._build_urls()

    def _build_urls(self):
        """Build service URLs based on deployment mode with environment overrides."""
        protocol = os.getenv("SERVICE_PROTOCOL", "http")

        # Get custom service host if provided (for self-hosted scenarios)
        custom_service_host = os.getenv("SERVICE_HOST")

        for key, service_info in self.SERVICES.items():
            port = service_info["port"]
            service_name = service_info["name"]

            # Check for service-specific environment variable override
            # Format: {SERVICE_KEY}_SERVICE_URL (e.g., AUTH_SERVICE_URL, SCAN_SERVICE_URL)
            env_var_name = f"{key.upper()}_SERVICE_URL"
            env_override = os.getenv(env_var_name)

            if env_override:
                # Service-specific override takes highest priority
                url = env_override
                logger.info(f"Service {key}: Using env override {env_var_name}")
            elif self._config.is_docker:
                # In Docker/Docker Compose: Use service name from docker-compose.yml
                url = f"{protocol}://{service_name}:{port}"
            elif custom_service_host:
                # Custom host provided (self-hosted with specific hostname/IP)
                url = f"{protocol}://{custom_service_host}:{port}"
            else:
                # Local development: Use localhost
                url = f"{protocol}://localhost:{port}"

            self._url_cache[key] = url
            logger.debug(f"Service {key}: {url}")

    def get_url(self, service_key: str) -> str:
        """
        Get the URL for a service.

        Args:
            service_key: Service identifier (e.g., 'auth', 'scan', 'ai')

        Returns:
            The full URL for the service

        Raises:
            KeyError: If the service is not registered
        """
        if service_key not in self._url_cache:
            available = ", ".join(self._url_cache.keys())
            raise KeyError(f"Unknown service '{service_key}'. Available: {available}")
        return self._url_cache[service_key]

    def get_all_urls(self) -> dict[str, str]:
        """Get all service URLs as a dictionary."""
        return self._url_cache.copy()

    def get_service_name(self, service_key: str) -> str:
        """Get the service name/container name for a service key."""
        if service_key not in self.SERVICES:
            raise KeyError(f"Unknown service '{service_key}'")
        return self.SERVICES[service_key]["name"]

    def get_service_port(self, service_key: str) -> int:
        """Get the port for a service."""
        if service_key not in self.SERVICES:
            raise KeyError(f"Unknown service '{service_key}'")
        return self.SERVICES[service_key]["port"]

    def reload(self):
        """Reload URLs (useful when environment variables change)."""
        self._url_cache.clear()
        self._build_urls()

    def __repr__(self) -> str:
        """String representation showing all service URLs."""
        lines = ["ServiceRegistry:"]
        for key, url in sorted(self._url_cache.items()):
            lines.append(f"  {key}: {url}")
        return "\n".join(lines)


# Global singleton instance
_registry: ServiceRegistry | None = None


def get_registry() -> ServiceRegistry:
    """Get or create the global service registry."""
    global _registry
    if _registry is None:
        _registry = ServiceRegistry()
    return _registry


def get_service_url(service_key: str) -> str:
    """
    Convenience function to get a service URL.

    Args:
        service_key: Service identifier (e.g., 'auth', 'scan', 'ai')

    Returns:
        The full URL for the service
    """
    return get_registry().get_url(service_key)


def get_all_service_urls() -> dict[str, str]:
    """Get all service URLs."""
    return get_registry().get_all_urls()


def log_service_config():
    """Log the current service configuration (useful for debugging)."""
    config = get_config()
    registry = get_registry()

    logger.info(f"Platform Config: {config}")
    logger.info(f"Service Registry:\n{registry}")
