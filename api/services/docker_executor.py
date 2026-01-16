"""Docker container execution service for security tools."""

import io
import logging
import os
import tarfile
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

import docker
from docker.errors import APIError, ImageNotFound

logger = logging.getLogger(__name__)

# Default AWS profile - can be overridden by environment or passed dynamically
# When aws_profile is passed to start_execution, it will override this default
DEFAULT_AWS_PROFILE = os.environ.get("DEFAULT_AWS_PROFILE", "nubicustos-audit")

# Docker network name for security tools
# This is dynamically detected at runtime since Docker Compose prefixes
# network names with the project directory name (e.g., nubi_security-net)
_SECURITY_NETWORK_NAME: str | None = None


def _detect_security_network() -> str:
    """
    Detect the Docker network name for security tools.

    Docker Compose creates networks with names prefixed by the project directory
    (e.g., 'nubi_security-net' or 'nubicustos_security-net'). This function
    queries Docker to find the correct network name.

    Returns:
        The detected network name, or falls back to DOCKER_NETWORK env var.

    Raises:
        RuntimeError: If no suitable network is found.
    """
    global _SECURITY_NETWORK_NAME

    # Return cached value if already detected
    if _SECURITY_NETWORK_NAME is not None:
        return _SECURITY_NETWORK_NAME

    # Check for explicit configuration first
    explicit_network = os.environ.get("DOCKER_NETWORK", "").strip()
    if explicit_network:
        _SECURITY_NETWORK_NAME = explicit_network
        logger.info(f"Using explicitly configured Docker network: {explicit_network}")
        return _SECURITY_NETWORK_NAME

    # Try to detect the network dynamically
    try:
        client = docker.from_env()
        networks = client.networks.list()

        # Look for a network ending with '_security-net'
        for network in networks:
            if network.name.endswith("_security-net"):
                _SECURITY_NETWORK_NAME = network.name
                logger.info(f"Detected Docker security network: {_SECURITY_NETWORK_NAME}")
                return _SECURITY_NETWORK_NAME

        # No matching network found
        raise RuntimeError(
            "No Docker network ending with '_security-net' found. "
            "Ensure docker-compose is running, or set DOCKER_NETWORK explicitly."
        )
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Failed to connect to Docker to detect network: {e}")


def get_security_network() -> str:
    """Get the Docker network name for security tools."""
    return _detect_security_network()


class ExecutionStatus(str, Enum):
    """Tool execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolType(str, Enum):
    """Supported tool types for Docker-based execution."""

    # AWS Security Tools
    PROWLER = "prowler"
    SCOUTSUITE = "scoutsuite"
    CLOUDFOX = "cloudfox"
    CLOUDSPLOIT = "cloudsploit"
    CLOUD_CUSTODIAN = "cloud-custodian"
    CLOUDMAPPER = "cloudmapper"
    CARTOGRAPHY = "cartography"
    PACU = "pacu"
    ENUMERATE_IAM = "enumerate-iam"
    # Kubernetes Security Tools
    KUBESCAPE = "kubescape"
    # IaC Security Tools
    CHECKOV = "checkov"
    TERRASCAN = "terrascan"
    TFSEC = "tfsec"
    KUBE_LINTER = "kube-linter"
    POLARIS = "polaris"


# Build configurations for tools that use local images
# Maps tool type to build context path relative to project root
# container_context is the path inside the API container (mounted via docker-compose)
LOCAL_BUILD_CONFIGS = {
    ToolType.CLOUDFOX: {
        "context": "docker/cloudfox",
        "container_context": "/app/docker/cloudfox",
        "dockerfile": "Dockerfile",
        "image": "cloudfox:local",
    },
    ToolType.ENUMERATE_IAM: {
        "context": "tools/enumerate-iam",
        "container_context": "/app/tools/enumerate-iam",
        "dockerfile": "Dockerfile",
        "image": "enumerate-iam:local",
    },
    ToolType.CLOUDSPLOIT: {
        "context": "docker/cloudsploit",
        "container_context": "/app/docker/cloudsploit",
        "dockerfile": "Dockerfile",
        "image": "cloudsploit:local",
    },
    ToolType.CLOUDMAPPER: {
        "context": "cloudmapper",
        "container_context": "/app/cloudmapper",
        "dockerfile": "Dockerfile",
        "image": "cloudmapper:local",
    },
}


# Tool configuration mapping - images match docker-compose.yml
TOOL_CONFIGS = {
    # ============================================================================
    # AWS Security Tools
    # ============================================================================
    ToolType.PROWLER: {
        "image": "toniblyx/prowler:4.2.4",
        "container_name_prefix": "prowler-scan",
        "volumes": {
            "/app/reports/prowler": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/home/prowler/.aws", "mode": "ro"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/home/prowler/.aws/credentials",
            "AWS_CONFIG_FILE": "/home/prowler/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
            "HOME": "/home/prowler",
        },
        "default_command": [
            "aws",
            "--profile",
            DEFAULT_AWS_PROFILE,
            "--output-formats",
            "json-ocsf",
            "html",
            "csv",
            "--output-directory",
            "/reports",
        ],
        "expected_exit_codes": [0, 1, 3],  # 0=no findings, 1/3=findings found (not errors)
    },
    ToolType.SCOUTSUITE: {
        "image": "rossja/ncc-scoutsuite:latest",
        "container_name_prefix": "scoutsuite-scan",
        "volumes": {
            "/app/reports/scoutsuite": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "entrypoint": "scout",  # Image has no entrypoint, must specify
        "default_command": [
            "--provider",
            "aws",
            "--profile",
            DEFAULT_AWS_PROFILE,
            "--report-dir",
            "/reports/aws",
            "--no-browser",
            "--force",
        ],
        "expected_exit_codes": [0, 1, 200],  # 200 = completed with warnings
    },
    ToolType.CLOUDFOX: {
        "image": "cloudfox:local",
        "container_name_prefix": "cloudfox-exec",
        "volumes": {
            "/app/reports/cloudfox": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "named_volumes": {
            "cloud-stack_cloudfox-data": {"bind": "/root/.cloudfox", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "entrypoint": "cloudfox",  # Image has no entrypoint, must specify
        "default_command": ["aws", "all-checks", "-o", "/reports", "--profile", DEFAULT_AWS_PROFILE],
        "expected_exit_codes": [0, 1],
    },
    ToolType.CLOUDSPLOIT: {
        "image": "cloudsploit:local",
        "container_name_prefix": "cloudsploit-scan",
        "volumes": {
            "/app/reports/cloudsploit": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "HOME": "/root",
            "AWS_DEFAULT_REGION": "us-east-1",
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "entrypoint": "node",
        "default_command": [
            "/var/scan/cloudsploit/index.js",
            "--cloud",
            "aws",
            "--compliance",
            "pci",
            "--console",
            "table",
            "--json",
            "/reports/output.json",
        ],
        "expected_exit_codes": [0, 1],
    },
    ToolType.CLOUD_CUSTODIAN: {
        "image": "cloudcustodian/c7n:latest",
        "container_name_prefix": "custodian-scan",
        "volumes": {
            "/app/policies": {"bind": "/policies", "mode": "ro"},
            "/app/reports/custodian": {"bind": "/output", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "default_command": ["run", "-s", "/output", "/policies/default.yml"],
        "expected_exit_codes": [0, 1],
    },
    ToolType.CLOUDMAPPER: {
        "image": "cloudmapper:local",
        "container_name_prefix": "cloudmapper-scan",
        "volumes": {
            "/app/reports/cloudmapper": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
            "/app/config/cloudmapper": {"bind": "/config", "mode": "ro"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "default_command": ["collect", "--config", "/config/config.json", "--output", "/reports"],
        "expected_exit_codes": [0],
    },
    ToolType.CARTOGRAPHY: {
        "image": "ghcr.io/lyft/cartography:0.94.0",
        "container_name_prefix": "cartography-scan",
        "volumes": {
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "NEO4J_URI": "bolt://neo4j:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "${NEO4J_PASSWORD:-cloudsecurity}",
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "default_command": [
            "--neo4j-uri",
            "bolt://neo4j:7687",
            "--neo4j-user",
            "neo4j",
            "--neo4j-password-env-var",
            "NEO4J_PASSWORD",
        ],
        "expected_exit_codes": [0],
    },
    ToolType.PACU: {
        "image": "rhinosecuritylabs/pacu:latest",
        "container_name_prefix": "pacu-exec",
        "volumes": {
            "/app/reports/pacu": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "named_volumes": {
            "cloud-stack_pacu-data": {"bind": "/root/.local/share/pacu", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "default_command": [],  # Pacu requires interactive session or specific module
        "expected_exit_codes": [0],
    },
    ToolType.ENUMERATE_IAM: {
        "image": "enumerate-iam:local",
        "container_name_prefix": "enumerate-iam-exec",
        "volumes": {
            "/app/reports/enumerate-iam": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
            "AWS_PROFILE": DEFAULT_AWS_PROFILE,
        },
        "default_command": ["--output-file", "/reports/iam-permissions.json"],
        "expected_exit_codes": [0],
    },
    # ============================================================================
    # Kubernetes Security Tools
    # ============================================================================
    ToolType.KUBESCAPE: {
        "image": "quay.io/armosec/kubescape:latest",
        "container_name_prefix": "kubescape-scan",
        "volumes": {
            "/app/kubeconfigs": {"bind": "/root/.kube", "mode": "ro"},
            "/app/reports/kubescape": {"bind": "/reports", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {},
        "default_command": [
            "scan",
            "--format",
            "json",
            "--output",
            "/reports/kubescape-results.json",
            "--submit=false",
        ],
        "expected_exit_codes": [0, 1],
    },
    # ============================================================================
    # IaC Security Tools
    # ============================================================================
    ToolType.CHECKOV: {
        "image": "bridgecrew/checkov:3.2.74",
        "container_name_prefix": "checkov-scan",
        "volumes": {
            # Note: /code mount is provided dynamically via extra_volumes in IaC orchestrator
            "/app/reports/checkov": {"bind": "/reports", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {},
        "default_command": [
            "-d",
            "/code",
            "--output",
            "json",
            "--output-file-path",
            "/reports",
            "--framework",
            "terraform",
            "cloudformation",
            "kubernetes",
            "helm",
            "arm",
            "--quiet",
        ],
        "expected_exit_codes": [0, 1],  # 1 = findings found (not an error)
    },
    ToolType.TERRASCAN: {
        "image": "tenable/terrascan:latest",
        "container_name_prefix": "terrascan-scan",
        "volumes": {
            # Note: /iac mount is provided dynamically via extra_volumes in IaC orchestrator
            "/app/reports/terrascan": {"bind": "/reports", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {},
        "entrypoint": "/go/bin/terrascan",
        "default_command": [
            "scan",
            "-d",
            "/iac",
            "-o",
            "json",
            "-f",
            "/reports/terrascan-results.json",
        ],
        "expected_exit_codes": [0, 1],  # 0 = no violations, 1 = violations found
    },
    ToolType.TFSEC: {
        "image": "aquasec/tfsec:v1.28.6",
        "container_name_prefix": "tfsec-scan",
        "volumes": {
            # Note: /src mount is provided dynamically via extra_volumes in IaC orchestrator
            "/app/reports/tfsec": {"bind": "/reports", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {},
        "default_command": [
            "/src",
            "--format",
            "json",
            "--out",
            "/reports/tfsec-results.json",
            "--soft-fail",
        ],
        "expected_exit_codes": [0, 1],  # 1 = findings found (not an error)
    },
    ToolType.KUBE_LINTER: {
        "image": "stackrox/kube-linter:v0.6.8",
        "container_name_prefix": "kube-linter-scan",
        "volumes": {
            # Note: /manifests mount is provided dynamically via extra_volumes in IaC orchestrator
            "/app/reports/kube-linter": {"bind": "/reports", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {},
        "default_command": [
            "lint",
            "/manifests",
            "--format",
            "json",
        ],
        "expected_exit_codes": [0, 1],  # 1 = findings found (not an error)
    },
    ToolType.POLARIS: {
        "image": "quay.io/fairwinds/polaris:9.0.1",
        "container_name_prefix": "polaris-scan",
        "volumes": {
            # Note: /manifests mount is provided dynamically via extra_volumes in IaC orchestrator
            "/app/reports/polaris": {"bind": "/reports", "mode": "rw"},
        },
        "network": None,  # Resolved dynamically via get_security_network()
        "environment": {},
        "default_command": [
            "audit",
            "--audit-path",
            "/manifests",
            "--format",
            "json",
            "--output-file",
            "/reports/polaris-results.json",
            "--set-exit-code-on-danger",
        ],
        "expected_exit_codes": [0, 1, 3],  # 0 = pass, 1 = warnings, 3 = danger-level issues
    },
}


# Scan profile definitions - which tools to run for each profile
SCAN_PROFILES = {
    "quick": {
        "tools": [ToolType.PROWLER],
        "description": "Fast scan focusing on critical/high severity issues (5-10 min)",
        "duration_estimate": "5-10 minutes",
        "prowler_options": ["--severity", "critical", "high"],
    },
    "comprehensive": {
        "tools": [
            ToolType.PROWLER,
            ToolType.SCOUTSUITE,
            ToolType.CLOUDFOX,
            ToolType.CLOUDSPLOIT,
            ToolType.CLOUD_CUSTODIAN,
            # CloudMapper removed: visualization tool requiring manual account config
            # Cartography removed: graph analysis tool requiring Neo4j setup
        ],
        "description": "Full security audit with all AWS security scanning tools (20-40 min)",
        "duration_estimate": "20-40 minutes",
        "prowler_options": [],
    },
    "compliance-only": {
        "tools": [ToolType.PROWLER, ToolType.SCOUTSUITE],
        "description": "Compliance framework focused scanning - CIS, SOC2, PCI-DSS, HIPAA (15-20 min)",
        "duration_estimate": "15-20 minutes",
        "prowler_options": ["--compliance", "cis_2.0_aws", "soc2_aws", "pci_3.2.1_aws", "hipaa_aws"],
        # scoutsuite_options removed - causes path handling bug
    },
}

# IaC Scan profile definitions - which tools to run for each IaC profile
IAC_SCAN_PROFILES = {
    "iac-quick": {
        "tools": [ToolType.CHECKOV],
        "description": "Fast IaC scan with Checkov only (1-3 min)",
        "duration_estimate": "1-3 minutes",
        "supported_frameworks": ["terraform", "cloudformation", "kubernetes", "helm", "arm"],
    },
    "iac-comprehensive": {
        "tools": [ToolType.CHECKOV, ToolType.TERRASCAN, ToolType.TFSEC],
        "description": "Full IaC security scan with multiple tools (5-10 min)",
        "duration_estimate": "5-10 minutes",
        "supported_frameworks": ["terraform", "cloudformation", "kubernetes", "helm", "arm"],
    },
    "kubernetes-manifests": {
        "tools": [ToolType.KUBE_LINTER, ToolType.POLARIS],
        "description": "Kubernetes manifest security scanning (2-5 min)",
        "duration_estimate": "2-5 minutes",
        "supported_frameworks": ["kubernetes", "helm"],
    },
}


class DockerExecutor:
    """Service for executing security tools in Docker containers."""

    def __init__(self):
        """Initialize the Docker client."""
        self._client: docker.DockerClient | None = None
        self._base_path = os.environ.get("HOST_PATH", "/app")

    @property
    def client(self) -> docker.DockerClient:
        """Get or create Docker client."""
        if self._client is None:
            try:
                # Try multiple connection methods
                socket_path = "/var/run/docker.sock"

                # Method 1: Direct Unix socket connection (Linux/Docker Desktop)
                if os.path.exists(socket_path):
                    try:
                        self._client = docker.DockerClient(base_url=f"unix://{socket_path}")
                        self._client.ping()
                        logger.info("Docker client connected via Unix socket")
                        return self._client
                    except Exception as e:
                        logger.warning(f"Unix socket connection failed: {e}")

                # Method 2: Environment-based connection (TCP/npipe)
                try:
                    self._client = docker.from_env()
                    self._client.ping()
                    logger.info("Docker client connected via environment")
                    return self._client
                except Exception as e:
                    logger.warning(f"Environment connection failed: {e}")

                # Method 3: Try TCP connection to Docker daemon
                try:
                    self._client = docker.DockerClient(base_url="tcp://localhost:2375")
                    self._client.ping()
                    logger.info("Docker client connected via TCP")
                    return self._client
                except Exception as e:
                    logger.warning(f"TCP connection failed: {e}")

                raise RuntimeError("All Docker connection methods failed")

            except Exception as e:
                logger.error(f"Failed to connect to Docker: {e}")
                raise RuntimeError(f"Docker connection failed: {e}")
        return self._client

    def _resolve_path(self, path: str) -> str:
        """Resolve container paths to host paths."""
        # When running inside a container, we need to map paths
        # from container perspective to host perspective
        if path.startswith("/app"):
            # Use HOST_PROJECT_PATH for /app mapping (project root)
            host_base = os.environ.get("HOST_PROJECT_PATH", "").strip()
            if not host_base:
                raise RuntimeError(
                    "HOST_PROJECT_PATH environment variable is not set. "
                    "This is required for volume mounting when running scans. "
                    "Ensure docker-compose is run from the project directory, "
                    "or set HOST_PROJECT_PATH explicitly in your .env file."
                )
            if not host_base.startswith("/"):
                raise RuntimeError(
                    f"HOST_PROJECT_PATH must be an absolute path, got: {host_base}"
                )
            return path.replace("/app", host_base)
        return path

    def _ensure_volume_exists(self, volume_name: str) -> None:
        """Ensure a named volume exists, creating it if necessary."""
        try:
            self.client.volumes.get(volume_name)
        except docker.errors.NotFound:
            logger.info(f"Creating volume: {volume_name}")
            self.client.volumes.create(volume_name)

    def _image_exists(self, image_name: str) -> bool:
        """Check if a Docker image exists locally."""
        try:
            self.client.images.get(image_name)
            return True
        except docker.errors.ImageNotFound:
            return False
        except Exception as e:
            logger.warning(f"Error checking for image {image_name}: {e}")
            return False

    def _create_build_context_tar(self, context_path: str, dockerfile: str = "Dockerfile") -> io.BytesIO:
        """
        Create a tar archive of the build context for streaming to Docker.

        Args:
            context_path: Path to the build context directory
            dockerfile: Name of the Dockerfile

        Returns:
            BytesIO object containing the tar archive
        """
        tar_stream = io.BytesIO()

        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            # Walk the context directory and add all files
            for root, dirs, files in os.walk(context_path):
                # Skip common ignore patterns
                dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", "node_modules", ".venv"]]

                for file in files:
                    file_path = os.path.join(root, file)
                    # Calculate archive name (relative to context)
                    arcname = os.path.relpath(file_path, context_path)
                    tar.add(file_path, arcname=arcname)

        tar_stream.seek(0)
        return tar_stream

    def _build_image(self, tool_type: ToolType) -> tuple[bool, str]:
        """
        Build a Docker image for a tool that requires local build.

        Uses the container-mounted path to access the build context and streams
        it as a tar archive to Docker, avoiding host path translation issues.

        Args:
            tool_type: The type of tool to build

        Returns:
            Tuple of (success, message)
        """
        build_config = LOCAL_BUILD_CONFIGS.get(tool_type)
        if not build_config:
            return False, f"No build configuration for {tool_type}"

        # Use the container-mounted path to access build context
        # This is mounted via docker-compose: ./tools:/app/tools:ro, ./docker:/app/docker:ro
        container_context = build_config.get("container_context")
        if not container_context:
            # Fallback to constructing path from context relative path
            container_context = os.path.join("/app", build_config["context"])

        dockerfile_name = build_config["dockerfile"]
        image_tag = build_config["image"]

        logger.info(f"Building image {image_tag} from container context {container_context}")

        # Verify the context path exists
        if not os.path.isdir(container_context):
            error_msg = (
                f"Build context not found at {container_context}. "
                f"Ensure the tools directory is mounted in docker-compose.yml"
            )
            logger.error(error_msg)
            return False, error_msg

        # Verify Dockerfile exists
        dockerfile_path = os.path.join(container_context, dockerfile_name)
        if not os.path.isfile(dockerfile_path):
            error_msg = f"Dockerfile not found at {dockerfile_path}"
            logger.error(error_msg)
            return False, error_msg

        try:
            # Create tar archive of the build context
            logger.debug(f"Creating tar archive of build context: {container_context}")
            tar_stream = self._create_build_context_tar(container_context, dockerfile_name)

            # Build the image using the tar stream
            # This avoids host path issues as Docker receives the context directly
            logger.info(f"Starting Docker build for {image_tag}...")
            image, build_logs = self.client.images.build(
                fileobj=tar_stream,
                custom_context=True,
                dockerfile=dockerfile_name,
                tag=image_tag,
                rm=True,  # Remove intermediate containers
                forcerm=True,  # Always remove intermediate containers
            )

            # Log build output
            for log_entry in build_logs:
                if "stream" in log_entry:
                    log_line = log_entry["stream"].strip()
                    if log_line:
                        logger.debug(log_line)
                elif "error" in log_entry:
                    logger.error(f"Build error: {log_entry['error']}")
                    return False, f"Build error: {log_entry['error']}"

            logger.info(f"Successfully built image {image_tag}")
            return True, f"Successfully built image {image_tag}"

        except docker.errors.BuildError as e:
            error_msg = f"Failed to build image {image_tag}: {e}"
            logger.error(error_msg)
            # Try to extract more details from build log
            if hasattr(e, "build_log"):
                for log_entry in e.build_log:
                    if "error" in log_entry:
                        error_msg += f"\nBuild log: {log_entry.get('error', '')}"
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error building image {image_tag}: {e}"
            logger.error(error_msg)
            return False, error_msg

    def _ensure_image_available(self, tool_type: ToolType) -> tuple[bool, str]:
        """
        Ensure the Docker image for a tool is available, building if necessary.

        Args:
            tool_type: The type of tool

        Returns:
            Tuple of (success, message)
        """
        config = TOOL_CONFIGS.get(tool_type)
        if not config:
            return False, f"Unknown tool type: {tool_type}"

        image_name = config["image"]

        # Check if image already exists
        if self._image_exists(image_name):
            logger.debug(f"Image {image_name} already exists")
            return True, f"Image {image_name} is available"

        # Check if this tool requires a local build
        if tool_type in LOCAL_BUILD_CONFIGS:
            logger.info(f"Image {image_name} not found, building...")
            return self._build_image(tool_type)

        # For images from registries, try to pull
        try:
            logger.info(f"Pulling image {image_name}...")
            self.client.images.pull(image_name)
            return True, f"Successfully pulled image {image_name}"
        except Exception as e:
            return False, f"Failed to pull image {image_name}: {e}"

    def _get_volumes(self, tool_type: ToolType) -> dict[str, dict[str, str]]:
        """Get volume mappings for a tool."""
        config = TOOL_CONFIGS.get(tool_type, {})
        volumes = {}

        # Map the volumes with resolved paths
        base_volumes = config.get("volumes", {})
        for container_path, mount_config in base_volumes.items():
            host_path = self._resolve_path(container_path)
            volumes[host_path] = mount_config

        # Add named volumes (these don't need path resolution)
        named_volumes = config.get("named_volumes", {})
        for volume_name, mount_config in named_volumes.items():
            self._ensure_volume_exists(volume_name)
            volumes[volume_name] = mount_config

        return volumes

    async def start_execution(
        self,
        tool_type: ToolType,
        command: list[str] | None = None,
        environment: dict[str, str] | None = None,
        extra_volumes: dict[str, dict[str, str]] | None = None,
        entrypoint: str | None = None,
    ) -> dict[str, Any]:
        """
        Start a tool execution in a container.

        Args:
            tool_type: The type of tool to execute
            command: Optional custom command to run
            environment: Optional additional environment variables
            extra_volumes: Optional additional volume mounts

        Returns:
            Execution info including execution_id and status
        """
        execution_id = str(uuid.uuid4())[:12]
        config = TOOL_CONFIGS.get(tool_type)

        if not config:
            raise ValueError(f"Unknown tool type: {tool_type}")

        container_name = f"{config['container_name_prefix']}-{execution_id}"

        try:
            # Ensure image is available (build if necessary)
            image_available, image_message = self._ensure_image_available(tool_type)
            if not image_available:
                logger.error(f"Image not available for {tool_type}: {image_message}")
                return {
                    "execution_id": execution_id,
                    "status": ExecutionStatus.FAILED,
                    "error": image_message,
                }

            # Prepare volumes
            volumes = self._get_volumes(tool_type)
            if extra_volumes:
                volumes.update(extra_volumes)

            # Prepare environment
            env = dict(config.get("environment", {}))
            if environment:
                env.update(environment)

            # Get command
            cmd = command if command else config.get("default_command", [])

            logger.info(f"Starting {tool_type} execution: {execution_id}")
            logger.debug(f"Image: {config['image']}, Command: {cmd}")

            # Resolve network - use config value if set, otherwise detect dynamically
            network = config.get("network")
            if network is None:
                network = get_security_network()

            # Run container in detached mode
            run_kwargs = {
                "image": config["image"],
                "name": container_name,
                "command": cmd if cmd else None,
                "environment": env,
                "volumes": volumes,
                "network": network,
                "detach": True,
                "remove": False,  # Keep container for log retrieval
                "auto_remove": False,
            }

            # Add entrypoint override if specified
            if entrypoint is not None:
                run_kwargs["entrypoint"] = entrypoint

            container = self.client.containers.run(**run_kwargs)

            return {
                "execution_id": execution_id,
                "container_id": container.id,
                "container_name": container_name,
                "status": ExecutionStatus.RUNNING,
                "tool_type": tool_type,
                "started_at": datetime.utcnow().isoformat(),
            }

        except ImageNotFound as e:
            logger.error(f"Image not found for {tool_type}: {e}")
            return {
                "execution_id": execution_id,
                "status": ExecutionStatus.FAILED,
                "error": f"Docker image not found: {config['image']}",
            }
        except APIError as e:
            logger.error(f"Docker API error: {e}")
            return {
                "execution_id": execution_id,
                "status": ExecutionStatus.FAILED,
                "error": f"Docker API error: {str(e)}",
            }
        except Exception as e:
            logger.error(f"Failed to start {tool_type} execution: {e}")
            return {
                "execution_id": execution_id,
                "status": ExecutionStatus.FAILED,
                "error": str(e),
            }

    async def get_execution_status(
        self,
        container_id: str,
    ) -> dict[str, Any]:
        """
        Get the status of a running execution.

        Args:
            container_id: The Docker container ID

        Returns:
            Execution status info
        """
        try:
            container = self.client.containers.get(container_id)
            status = container.status

            result = {
                "container_id": container_id,
                "status": status,
            }

            if status == "exited":
                exit_code = container.attrs["State"]["ExitCode"]
                result["exit_code"] = exit_code
                result["execution_status"] = (
                    ExecutionStatus.COMPLETED if exit_code == 0 else ExecutionStatus.FAILED
                )
                # Get logs
                logs = container.logs(tail=100).decode("utf-8", errors="replace")
                result["logs"] = logs
            elif status == "running":
                result["execution_status"] = ExecutionStatus.RUNNING
            elif status == "dead":
                # Container crashed or failed to start properly
                result["execution_status"] = ExecutionStatus.FAILED
                result["error"] = "Container died unexpectedly"
                logs = container.logs(tail=100).decode("utf-8", errors="replace")
                result["logs"] = logs
            else:
                # "created", "paused", "restarting", "removing" - report as PENDING
                # The caller should handle these states appropriately
                result["execution_status"] = ExecutionStatus.PENDING

            return result

        except docker.errors.NotFound:
            return {
                "container_id": container_id,
                "status": "not_found",
                "execution_status": ExecutionStatus.FAILED,
                "error": "Container not found",
            }
        except Exception as e:
            logger.error(f"Failed to get execution status: {e}")
            return {
                "container_id": container_id,
                "execution_status": ExecutionStatus.FAILED,
                "error": str(e),
            }

    async def get_execution_logs(
        self,
        container_id: str,
        tail: int = 100,
    ) -> str:
        """
        Get logs from a container.

        Args:
            container_id: The Docker container ID
            tail: Number of lines to retrieve

        Returns:
            Container logs as string
        """
        try:
            container = self.client.containers.get(container_id)
            logs = container.logs(tail=tail).decode("utf-8", errors="replace")
            return logs
        except Exception as e:
            logger.error(f"Failed to get logs: {e}")
            return f"Error retrieving logs: {e}"

    async def stop_execution(
        self,
        container_id: str,
    ) -> dict[str, Any]:
        """
        Stop a running execution.

        Args:
            container_id: The Docker container ID

        Returns:
            Stop result info
        """
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=10)
            return {
                "container_id": container_id,
                "status": "stopped",
                "execution_status": ExecutionStatus.CANCELLED,
            }
        except Exception as e:
            logger.error(f"Failed to stop execution: {e}")
            return {
                "container_id": container_id,
                "error": str(e),
            }

    async def cleanup_container(
        self,
        container_id: str,
    ) -> bool:
        """
        Remove a container after execution.

        Args:
            container_id: The Docker container ID

        Returns:
            True if successful
        """
        try:
            container = self.client.containers.get(container_id)
            container.remove(force=True)
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup container: {e}")
            return False

    def is_available(self) -> bool:
        """Check if Docker is available."""
        try:
            self.client.ping()
            return True
        except Exception:
            return False


# Singleton instance
_executor: DockerExecutor | None = None


def get_docker_executor() -> DockerExecutor:
    """Get or create the Docker executor singleton."""
    global _executor
    if _executor is None:
        _executor = DockerExecutor()
    return _executor
