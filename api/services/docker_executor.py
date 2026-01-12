"""Docker container execution service for security tools."""

import logging
import os
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

import docker
from docker.errors import APIError, ImageNotFound

logger = logging.getLogger(__name__)


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
        "network": "cloud-stack_security-net",
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/home/prowler/.aws/credentials",
            "AWS_CONFIG_FILE": "/home/prowler/.aws/config",
            "HOME": "/home/prowler",
        },
        "default_command": [
            "aws",
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
        "image": "opendevsecops/scoutsuite:5.12.0",
        "container_name_prefix": "scoutsuite-scan",
        "volumes": {
            "/app/reports/scoutsuite": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": "cloud-stack_security-net",
        "environment": {},
        "default_command": [
            "--provider",
            "aws",
            "--report-dir",
            "/reports/aws",
            "--no-browser",
            "--force",
        ],
        "expected_exit_codes": [0, 1],
    },
    ToolType.CLOUDFOX: {
        "image": "bishopfox/cloudfox:1.14.2",
        "container_name_prefix": "cloudfox-exec",
        "volumes": {
            "/app/reports/cloudfox": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "named_volumes": {
            "cloud-stack_cloudfox-data": {"bind": "/root/.cloudfox", "mode": "rw"},
        },
        "network": "cloud-stack_security-net",
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
            "AWS_CONFIG_FILE": "/root/.aws/config",
        },
        "default_command": ["aws", "all-checks", "--output", "/reports"],
        "expected_exit_codes": [0, 1],
    },
    ToolType.CLOUDSPLOIT: {
        "image": "cloudsploit:local",
        "container_name_prefix": "cloudsploit-scan",
        "volumes": {
            "/app/reports/cloudsploit": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": "cloud-stack_security-net",
        "environment": {
            "HOME": "/root",
            "AWS_DEFAULT_REGION": "us-east-1",
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
        "image": "cloudcustodian/c7n:0.9.34",
        "container_name_prefix": "custodian-scan",
        "volumes": {
            "/app/policies": {"bind": "/policies", "mode": "ro"},
            "/app/reports/custodian": {"bind": "/output", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "network": "cloud-stack_security-net",
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
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
        "network": "cloud-stack_security-net",
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
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
        "network": "cloud-stack_security-net",
        "environment": {
            "NEO4J_URI": "bolt://neo4j:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "${NEO4J_PASSWORD:-cloudsecurity}",
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
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
        "image": "rhinosecuritylabs/pacu:1.6.0",
        "container_name_prefix": "pacu-exec",
        "volumes": {
            "/app/reports/pacu": {"bind": "/reports", "mode": "rw"},
            "/app/credentials/aws": {"bind": "/root/.aws", "mode": "ro"},
        },
        "named_volumes": {
            "cloud-stack_pacu-data": {"bind": "/root/.local/share/pacu", "mode": "rw"},
        },
        "network": "cloud-stack_security-net",
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
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
        "network": "cloud-stack_security-net",
        "environment": {
            "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
        },
        "default_command": ["--output-file", "/reports/iam-permissions.json"],
        "expected_exit_codes": [0],
    },
    # ============================================================================
    # Kubernetes Security Tools
    # ============================================================================
    ToolType.KUBESCAPE: {
        "image": "quay.io/armosec/kubescape:v3.0.8",
        "container_name_prefix": "kubescape-scan",
        "volumes": {
            "/app/kubeconfigs": {"bind": "/root/.kube", "mode": "ro"},
            "/app/reports/kubescape": {"bind": "/reports", "mode": "rw"},
        },
        "network": "cloud-stack_security-net",
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
            ToolType.CLOUDMAPPER,
            ToolType.CARTOGRAPHY,
        ],
        "description": "Full security audit with all AWS tools (30-60 min)",
        "duration_estimate": "30-60 minutes",
        "prowler_options": [],
    },
    "compliance-only": {
        "tools": [ToolType.PROWLER, ToolType.SCOUTSUITE],
        "description": "Compliance framework focused scanning - CIS, SOC2, PCI-DSS, HIPAA (15-20 min)",
        "duration_estimate": "15-20 minutes",
        "prowler_options": ["--compliance", "cis_2.0_aws", "soc2_aws", "pci_dss_v4.0_aws"],
        "scoutsuite_options": ["--ruleset", "cis"],
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
            host_base = os.environ.get("HOST_REPORTS_PATH", os.getcwd())
            return path.replace("/app", host_base)
        return path

    def _ensure_volume_exists(self, volume_name: str) -> None:
        """Ensure a named volume exists, creating it if necessary."""
        try:
            self.client.volumes.get(volume_name)
        except docker.errors.NotFound:
            logger.info(f"Creating volume: {volume_name}")
            self.client.volumes.create(volume_name)

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

            # Run container in detached mode
            run_kwargs = {
                "image": config["image"],
                "name": container_name,
                "command": cmd if cmd else None,
                "environment": env,
                "volumes": volumes,
                "network": config.get("network"),
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
            else:
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
