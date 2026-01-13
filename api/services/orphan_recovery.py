"""
Orphan Recovery Service.

Detects and recovers orphaned scans and tool executions that were left in
"running" status when the API was restarted or crashed.

This service runs during API startup to:
1. Find scans in "running" status
2. Check if their associated containers are still running
3. Mark orphaned scans as "failed" with appropriate error messages
4. Clean up orphaned tool executions
"""

import logging
from datetime import datetime, timedelta

import docker
from docker.errors import NotFound as ContainerNotFound
from sqlalchemy.orm import Session

from models.database import Scan, ToolExecution

logger = logging.getLogger(__name__)


class OrphanRecoveryService:
    """Service to detect and recover orphaned scans and executions."""

    # Scans without linked executions are considered orphaned after this many hours
    UNLINKED_SCAN_TIMEOUT_HOURS = 1

    def __init__(self, db: Session, orphan_timeout_hours: int = 24):
        """
        Initialize the orphan recovery service.

        Args:
            db: Database session
            orphan_timeout_hours: Consider scans orphaned if running longer than this
        """
        self.db = db
        self.orphan_timeout_hours = orphan_timeout_hours
        self._docker_client = None

    @property
    def docker_client(self):
        """Lazy-load Docker client."""
        if self._docker_client is None:
            try:
                # Try Unix socket first (Linux/Mac), then named pipe (Windows)
                try:
                    self._docker_client = docker.DockerClient(
                        base_url="unix:///var/run/docker.sock"
                    )
                except Exception:
                    self._docker_client = docker.DockerClient(
                        base_url="npipe:////./pipe/docker_engine"
                    )
                logger.info("Docker client connected for orphan recovery")
            except Exception as e:
                logger.warning(f"Could not connect to Docker for orphan recovery: {e}")
                self._docker_client = None
        return self._docker_client

    def check_container_exists(self, container_id: str) -> dict:
        """
        Check if a container exists and get its status.

        Args:
            container_id: Docker container ID

        Returns:
            dict with keys: exists, status, exit_code (if exited)
        """
        if not self.docker_client or not container_id:
            return {"exists": False, "status": "unknown", "error": "No Docker client or container ID"}

        try:
            container = self.docker_client.containers.get(container_id)
            result = {
                "exists": True,
                "status": container.status,
            }
            if container.status == "exited":
                result["exit_code"] = container.attrs["State"]["ExitCode"]
            return result
        except ContainerNotFound:
            return {"exists": False, "status": "not_found"}
        except Exception as e:
            return {"exists": False, "status": "error", "error": str(e)}

    def recover_orphaned_scans(self) -> dict:
        """
        Find and mark orphaned scans as failed.

        A scan is considered orphaned if:
        1. Status is "running" or "pending"
        2. Started more than orphan_timeout_hours ago, OR
        3. Has execution_ids in metadata but none of those containers are running, OR
        4. Has no execution_ids and started more than UNLINKED_SCAN_TIMEOUT_HOURS ago

        Returns:
            dict with recovery statistics
        """
        stats = {
            "scans_checked": 0,
            "scans_recovered": 0,
            "scans_still_running": 0,
            "errors": [],
        }

        try:
            # Find all scans with running or pending status
            orphan_candidates = (
                self.db.query(Scan)
                .filter(Scan.status.in_(["running", "pending"]))
                .all()
            )

            stats["scans_checked"] = len(orphan_candidates)
            logger.info(f"Found {len(orphan_candidates)} scans in running/pending status")

            max_cutoff_time = datetime.utcnow() - timedelta(hours=self.orphan_timeout_hours)
            unlinked_cutoff_time = datetime.utcnow() - timedelta(hours=self.UNLINKED_SCAN_TIMEOUT_HOURS)

            for scan in orphan_candidates:
                try:
                    is_orphan = False
                    reason = ""

                    # Get execution_ids from scan metadata if available
                    metadata = scan.scan_metadata if scan.scan_metadata else {}
                    execution_ids = metadata.get("execution_ids", [])

                    # Check 1: Scan started too long ago (absolute max timeout)
                    if scan.started_at and scan.started_at < max_cutoff_time:
                        is_orphan = True
                        reason = f"Scan exceeded {self.orphan_timeout_hours}h timeout"

                    # Check 2: Scan has linked execution_ids - check if those containers are alive
                    elif execution_ids:
                        has_live_container = self._check_execution_ids_have_live_containers(execution_ids)
                        if not has_live_container:
                            is_orphan = True
                            reason = "Linked containers no longer running"

                    # Check 3: Scan has no linked execution_ids (orphaned before any tool started)
                    # Use shorter timeout since we can't verify container status
                    elif scan.started_at and scan.started_at < unlinked_cutoff_time:
                        is_orphan = True
                        reason = f"No linked executions and exceeded {self.UNLINKED_SCAN_TIMEOUT_HOURS}h timeout"

                    if is_orphan:
                        self._mark_scan_as_failed(scan, reason)
                        stats["scans_recovered"] += 1
                        logger.info(
                            f"Recovered orphan scan {scan.scan_id}: {reason}"
                        )
                    else:
                        stats["scans_still_running"] += 1
                        logger.debug(f"Scan {scan.scan_id} appears to still be running")

                except Exception as e:
                    error_msg = f"Error processing scan {scan.scan_id}: {e}"
                    stats["errors"].append(error_msg)
                    logger.error(error_msg)

            self.db.commit()

        except Exception as e:
            error_msg = f"Error during scan recovery: {e}"
            stats["errors"].append(error_msg)
            logger.error(error_msg)

        return stats

    def _check_execution_ids_have_live_containers(self, execution_ids: list[str]) -> bool:
        """
        Check if any of the given execution IDs have live containers.

        Args:
            execution_ids: List of execution IDs to check

        Returns:
            True if any of the executions have running containers
        """
        if not self.docker_client or not execution_ids:
            return False

        for exec_id in execution_ids:
            # Find the execution record
            execution = (
                self.db.query(ToolExecution)
                .filter(ToolExecution.execution_id == exec_id)
                .first()
            )

            if execution and execution.container_id:
                container_status = self.check_container_exists(execution.container_id)
                if container_status.get("exists") and container_status.get("status") == "running":
                    return True

        return False

    def _mark_scan_as_failed(self, scan: Scan, reason: str) -> None:
        """
        Mark a scan as failed due to orphan recovery.

        Args:
            scan: The Scan object to update
            reason: The reason for marking as failed
        """
        scan.status = "failed"
        scan.completed_at = datetime.utcnow()

        # Update metadata with recovery info
        current_metadata = dict(scan.scan_metadata) if scan.scan_metadata else {}
        current_metadata["recovery"] = {
            "recovered_at": datetime.utcnow().isoformat(),
            "reason": reason,
            "original_status": "running",
        }
        scan.scan_metadata = current_metadata

    def recover_orphaned_tool_executions(self) -> dict:
        """
        Find and mark orphaned tool executions as failed.

        A tool execution is considered orphaned if:
        1. Status is "running"
        2. Container doesn't exist or has exited

        Returns:
            dict with recovery statistics
        """
        stats = {
            "executions_checked": 0,
            "executions_recovered": 0,
            "executions_still_running": 0,
            "errors": [],
        }

        try:
            # Find all tool executions with running status
            running_executions = (
                self.db.query(ToolExecution)
                .filter(ToolExecution.status == "running")
                .all()
            )

            stats["executions_checked"] = len(running_executions)
            logger.info(f"Found {len(running_executions)} tool executions in running status")

            for execution in running_executions:
                try:
                    if not execution.container_id:
                        # No container ID means it never started properly
                        self._mark_execution_as_failed(
                            execution, "No container ID recorded"
                        )
                        stats["executions_recovered"] += 1
                        continue

                    container_status = self.check_container_exists(execution.container_id)

                    if not container_status.get("exists"):
                        # Container doesn't exist
                        self._mark_execution_as_failed(
                            execution, "Container no longer exists"
                        )
                        stats["executions_recovered"] += 1
                    elif container_status.get("status") == "exited":
                        # Container exited but status wasn't updated
                        exit_code = container_status.get("exit_code", -1)
                        execution.exit_code = exit_code
                        if exit_code == 0:
                            execution.status = "completed"
                        else:
                            execution.status = "failed"
                            execution.error_message = f"Container exited with code {exit_code} (recovered)"
                        execution.completed_at = datetime.utcnow()
                        stats["executions_recovered"] += 1
                        logger.info(
                            f"Recovered execution {execution.execution_id} "
                            f"(exit code: {exit_code})"
                        )
                    elif container_status.get("status") == "running":
                        # Container is still running
                        stats["executions_still_running"] += 1
                        logger.debug(
                            f"Execution {execution.execution_id} still has running container"
                        )
                    else:
                        # Unknown status
                        self._mark_execution_as_failed(
                            execution, f"Unknown container status: {container_status}"
                        )
                        stats["executions_recovered"] += 1

                except Exception as e:
                    error_msg = f"Error processing execution {execution.execution_id}: {e}"
                    stats["errors"].append(error_msg)
                    logger.error(error_msg)

            self.db.commit()

        except Exception as e:
            error_msg = f"Error during execution recovery: {e}"
            stats["errors"].append(error_msg)
            logger.error(error_msg)

        return stats

    def _mark_execution_as_failed(self, execution: ToolExecution, reason: str) -> None:
        """
        Mark a tool execution as failed.

        Args:
            execution: The ToolExecution object to update
            reason: The reason for marking as failed
        """
        execution.status = "failed"
        execution.completed_at = datetime.utcnow()
        execution.error_message = f"Orphan recovery: {reason}"
        logger.info(f"Marked execution {execution.execution_id} as failed: {reason}")


async def run_orphan_recovery(db_url: str, orphan_timeout_hours: int = 24) -> dict:
    """
    Run orphan recovery process.

    This should be called during API startup.

    Args:
        db_url: Database connection URL
        orphan_timeout_hours: Consider scans orphaned after this many hours

    Returns:
        dict with recovery statistics
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    logger.info("Starting orphan recovery process...")

    results = {
        "scans": {},
        "executions": {},
    }

    try:
        engine = create_engine(db_url)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()

        try:
            service = OrphanRecoveryService(db, orphan_timeout_hours)

            # Recover orphaned scans
            results["scans"] = service.recover_orphaned_scans()

            # Recover orphaned tool executions
            results["executions"] = service.recover_orphaned_tool_executions()

            total_recovered = (
                results["scans"].get("scans_recovered", 0) +
                results["executions"].get("executions_recovered", 0)
            )

            if total_recovered > 0:
                logger.info(
                    f"Orphan recovery completed: "
                    f"{results['scans'].get('scans_recovered', 0)} scans, "
                    f"{results['executions'].get('executions_recovered', 0)} executions recovered"
                )
            else:
                logger.info("Orphan recovery completed: no orphans found")

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Orphan recovery failed: {e}")
        results["error"] = str(e)

    return results
