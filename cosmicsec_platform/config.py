"""
Cross-platform OS detection and environment-aware configuration.
Automatically detects the operating system and deployment environment
to apply appropriate configurations for services, paths, and connectivity.
"""

import os
import platform
import sys
from enum import Enum
from pathlib import Path


class OSType(Enum):
    """Supported operating systems."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class DeploymentMode(Enum):
    """Deployment modes with different configurations."""

    LOCAL_DEV = "local_dev"  # Local machine development (any OS)
    DOCKER = "docker"  # Docker container deployment
    DOCKER_COMPOSE = "docker_compose"  # Docker Compose environment
    KUBERNETES = "kubernetes"  # Kubernetes deployment
    SELF_HOSTED = "self_hosted"  # Home/self-hosted server


class PlatformConfig:
    """Detects OS, deployment mode, and provides environment-aware configuration."""

    _instance = None

    def __new__(cls):
        """Singleton pattern to ensure only one config instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize platform detection (only once due to singleton)."""
        if self._initialized:
            return

        self._os_type = self._detect_os()
        self._deployment_mode = self._detect_deployment_mode()
        self._setup_paths()
        self._initialized = True

    @staticmethod
    def _detect_os() -> OSType:
        """Detect the current operating system."""
        system = platform.system()
        os_mapping = {
            "Windows": OSType.WINDOWS,
            "Linux": OSType.LINUX,
            "Darwin": OSType.MACOS,
        }
        return os_mapping.get(system, OSType.UNKNOWN)

    @staticmethod
    def _detect_deployment_mode() -> DeploymentMode:
        """
        Detect the current deployment mode.

        Priority (checked in order):
        1. Explicit COSMICSEC_DEPLOYMENT_MODE environment variable
        2. Running inside Docker container
        3. Running inside Kubernetes
        4. DOCKER_COMPOSE flag or docker-compose process
        5. Default to LOCAL_DEV
        """
        # Check explicit environment variable first
        explicit_mode = os.getenv("COSMICSEC_DEPLOYMENT_MODE")
        if explicit_mode:
            try:
                return DeploymentMode(explicit_mode.lower())
            except ValueError:
                pass

        # Check if running in Docker
        if PlatformConfig._is_in_docker():
            # Check if it's Docker Compose
            if PlatformConfig._is_docker_compose():
                return DeploymentMode.DOCKER_COMPOSE
            return DeploymentMode.DOCKER

        # Check if running in Kubernetes
        if PlatformConfig._is_in_kubernetes():
            return DeploymentMode.KUBERNETES

        # Check for self-hosted environment
        if os.getenv("COSMICSEC_SELF_HOSTED") in ("1", "true", "yes"):
            return DeploymentMode.SELF_HOSTED

        # Default to local development
        return DeploymentMode.LOCAL_DEV

    @staticmethod
    def _is_in_docker() -> bool:
        """Check if running inside a Docker container."""
        # Method 1: Check /.dockerenv file (works for most Docker installations)
        if Path("/.dockerenv").exists():
            return True

        # Method 2: Check /proc/self/cgroup for docker/container references
        try:
            with open("/proc/self/cgroup") as f:
                content = f.read()
                if "docker" in content or "lxc" in content or "container" in content:
                    return True
        except (FileNotFoundError, PermissionError):
            pass

        # Method 3: Check for Docker environment variable
        return bool(os.getenv("DOCKER_HOST"))

    @staticmethod
    def _is_docker_compose() -> bool:
        """Check if running via Docker Compose."""
        # Check for docker-compose specific environment variables
        compose_markers = [
            "COMPOSE_PROJECT_NAME",
            "COMPOSE_SERVICE_NAME",
            "COMPOSE_CONTAINER_NAME",
        ]

        for marker in compose_markers:
            if os.getenv(marker):
                return True

        # Check if docker-compose process is running
        try:
            if sys.platform != "win32":  # Not Windows
                import subprocess

                result = subprocess.run(
                    ["pgrep", "-f", "docker-compose"], capture_output=True, timeout=2
                )
                return result.returncode == 0
        except Exception:
            pass

        return False

    @staticmethod
    def _is_in_kubernetes() -> bool:
        """Check if running inside Kubernetes."""
        # Kubernetes sets specific environment variables
        return bool(os.getenv("KUBERNETES_SERVICE_HOST"))

    def _setup_paths(self):
        """Setup OS-specific paths for data, logs, and configs."""
        home_dir = Path.home()

        if self._os_type == OSType.WINDOWS:
            self.app_data_dir = (
                Path(os.getenv("APPDATA", home_dir / "AppData" / "Roaming")) / "CosmicSec"
            )
            self.logs_dir = self.app_data_dir / "logs"
            self.cache_dir = (
                Path(os.getenv("LOCALAPPDATA", home_dir / "AppData" / "Local"))
                / "CosmicSec"
                / "cache"
            )
        else:  # Linux, macOS, etc.
            if self._os_type == OSType.MACOS:
                self.app_data_dir = home_dir / "Library" / "Application Support" / "CosmicSec"
                self.cache_dir = home_dir / "Library" / "Caches" / "CosmicSec"
            else:  # Linux
                self.app_data_dir = home_dir / ".config" / "cosmicsec"
                self.cache_dir = home_dir / ".cache" / "cosmicsec"

            self.logs_dir = self.app_data_dir / "logs"

        # Create directories if they don't exist
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @property
    def os_type(self) -> OSType:
        """Get the detected OS type."""
        return self._os_type

    @property
    def deployment_mode(self) -> DeploymentMode:
        """Get the detected deployment mode."""
        return self._deployment_mode

    @property
    def is_windows(self) -> bool:
        """Check if running on Windows."""
        return self._os_type == OSType.WINDOWS

    @property
    def is_linux(self) -> bool:
        """Check if running on Linux."""
        return self._os_type == OSType.LINUX

    @property
    def is_macos(self) -> bool:
        """Check if running on macOS."""
        return self._os_type == OSType.MACOS

    @property
    def is_local_dev(self) -> bool:
        """Check if in local development mode."""
        return self._deployment_mode == DeploymentMode.LOCAL_DEV

    @property
    def is_docker(self) -> bool:
        """Check if in Docker mode."""
        return self._deployment_mode in (DeploymentMode.DOCKER, DeploymentMode.DOCKER_COMPOSE)

    @property
    def is_self_hosted(self) -> bool:
        """Check if in self-hosted mode."""
        return self._deployment_mode == DeploymentMode.SELF_HOSTED

    def get_path_separator(self) -> str:
        """Get the OS-specific path separator."""
        return "\\" if self.is_windows else "/"

    def get_app_data_dir(self) -> Path:
        """Get the app data directory for the current OS."""
        return self.app_data_dir

    def get_logs_dir(self) -> Path:
        """Get the logs directory for the current OS."""
        return self.logs_dir

    def get_cache_dir(self) -> Path:
        """Get the cache directory for the current OS."""
        return self.cache_dir

    def get_config_file_path(self, filename: str = "cosmicsec.yaml") -> Path:
        """Get the path to a configuration file."""
        return self.app_data_dir / filename

    def __repr__(self) -> str:
        """String representation of the platform configuration."""
        return f"PlatformConfig(os={self._os_type.value}, deployment={self._deployment_mode.value})"


# Global singleton instance
config = PlatformConfig()


def get_config() -> PlatformConfig:
    """Get the global platform configuration instance."""
    return config
