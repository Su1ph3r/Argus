"""
Scans API Endpoints.

This module provides endpoints for managing security scans, including:
- Listing scans with pagination and filtering
- Triggering new security scans
- Retrieving scan details and status
- Cancelling running scans
- Listing available scan profiles

Scans orchestrate multiple security scanning tools (Prowler, ScoutSuite, Kubescape, etc.)
across AWS, Azure, GCP, and Kubernetes environments.

Endpoints:
    GET /scans - List all scans
    POST /scans - Trigger a new scan
    GET /scans/{scan_id} - Get scan details
    GET /scans/{scan_id}/status - Get scan status
    DELETE /scans/{scan_id} - Cancel a running scan
    GET /scans/profiles/list - List available scan profiles
"""

import asyncio
import logging
from datetime import datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from config import get_settings
from models.database import Scan, get_db
from models.schemas import ScanCreate, ScanListResponse, ScanResponse
from services.docker_executor import (
    SCAN_PROFILES,
    TOOL_CONFIGS,
    DockerExecutor,
    ExecutionStatus,
    ToolType,
    get_docker_executor,
)

router: APIRouter = APIRouter(prefix="/scans", tags=["Scans"])
logger: logging.Logger = logging.getLogger(__name__)

# Provider to tools mapping
PROVIDER_TOOLS: dict[str, list[str]] = {
    "aws": [
        "prowler",
        "scoutsuite",
        "cloudsploit",
        "custodian",
        "cloudmapper",
        "cartography",
        "pacu",
        "cloudfox",
        "enumerate-iam",
    ],
    "azure": ["prowler", "scoutsuite", "cloudfox"],
    "gcp": ["prowler", "scoutsuite", "cloudfox", "cartography"],
    "kubernetes": [
        "kube-bench",
        "kubescape",
        "kube-hunter",
        "trivy",
        "grype",
        "popeye",
        "kube-linter",
        "polaris",
        "falco",
    ],
    "iac": ["checkov", "terrascan", "tfsec"],
}


async def _process_scan_reports(
    scan_id: str,
    tools: list[str],
    executor: DockerExecutor,
) -> None:
    """
    Run the report processor to parse findings and link them to the scan.

    Args:
        scan_id: The orchestration scan UUID
        tools: List of tool names that were run (e.g., ['prowler', 'scoutsuite'])
        executor: Docker executor instance
    """
    import os

    # Build the command to run report processor with scan_id
    tools_arg = ",".join(tools)
    command = ["python", "/app/process_reports.py", "--scan-id", scan_id, "--tools", tools_arg]

    logger.info(f"Running report processor for scan {scan_id} with tools: {tools}")

    try:
        # Get host path for reports volume
        host_reports_path = os.environ.get("HOST_REPORTS_PATH", os.getcwd())

        # Run report processor container
        container = executor.client.containers.run(
            image="cloud-stack-report-processor",  # Use our local report-processor image
            command=command,
            name=f"report-processor-{scan_id[:8]}",
            volumes={
                f"{host_reports_path}/reports": {"bind": "/reports", "mode": "ro"},
                f"{host_reports_path}/processed": {"bind": "/processed", "mode": "rw"},
            },
            environment={
                "DB_HOST": os.environ.get("DB_HOST", "postgresql"),
                "DB_NAME": os.environ.get("DB_NAME", "security_audits"),
                "DB_USER": os.environ.get("DB_USER", "auditor"),
                "DB_PASSWORD": os.environ.get(
                    "DB_PASSWORD", os.environ.get("POSTGRES_PASSWORD", "")
                ),
                "ORCHESTRATION_SCAN_ID": scan_id,
                "TOOLS_TO_PROCESS": tools_arg,
            },
            network="cloud-stack_security-net",
            detach=False,  # Wait for completion
            remove=True,  # Auto-cleanup container
        )

        logger.info(f"Report processor completed for scan {scan_id}")

    except Exception as e:
        logger.error(f"Report processor failed for scan {scan_id}: {e}")
        # Fall back to direct processing if container approach fails
        await _process_reports_directly(scan_id, tools)


async def _process_reports_directly(scan_id: str, tools: list[str]) -> None:
    """
    Fall back to direct report processing within the API container.

    This is used when the report-processor container can't be launched.
    """
    import sys

    sys.path.insert(0, "/app/report-processor")

    try:
        from process_reports import ReportProcessor

        processor = ReportProcessor()
        processor.process_for_scan(scan_id, tools)
        logger.info(f"Direct report processing completed for scan {scan_id}")
    except ImportError as e:
        logger.error(f"Could not import ReportProcessor: {e}")
    except Exception as e:
        logger.error(f"Direct report processing failed: {e}")


async def run_scan_orchestration(
    scan_id: str,
    profile: str,
    severity_filter: str | None,
    db_url: str,
) -> None:
    """
    Background task to orchestrate a security scan using Docker SDK.

    Launches tools sequentially based on the scan profile, waiting for each
    to complete before starting the next.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # Create a new database session for background task
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    executor = get_docker_executor()
    profile_config = SCAN_PROFILES.get(profile)

    if not profile_config:
        logger.error(f"Unknown scan profile: {profile}")
        _update_scan_status(db, scan_id, "failed", error="Unknown profile")
        return

    tools: list[ToolType] = profile_config["tools"]
    execution_ids = []
    container_ids = []

    logger.info(
        f"Starting scan {scan_id} with profile '{profile}', tools: {[t.value for t in tools]}"
    )

    try:
        for tool in tools:
            logger.info(f"Scan {scan_id}: Starting tool {tool.value}")

            # Get tool config
            tool_config = TOOL_CONFIGS.get(tool, {})

            # Build command with profile-specific options
            command = None
            entrypoint = tool_config.get("entrypoint")

            if tool == ToolType.PROWLER:
                command = list(tool_config.get("default_command", []))
                # Add profile-specific options
                prowler_options = profile_config.get("prowler_options", [])
                if prowler_options:
                    command.extend(prowler_options)
                # Add severity filter if specified
                if severity_filter:
                    command.extend(["--severity", severity_filter])

            elif tool == ToolType.SCOUTSUITE:
                command = list(tool_config.get("default_command", []))
                # Add profile-specific options
                scoutsuite_options = profile_config.get("scoutsuite_options", [])
                if scoutsuite_options:
                    command.extend(scoutsuite_options)

            elif tool == ToolType.CLOUDSPLOIT:
                # CloudSploit needs special handling for entrypoint
                command = list(tool_config.get("default_command", []))

            else:
                # Use default command from config
                default_cmd = tool_config.get("default_command", [])
                if default_cmd:
                    command = list(default_cmd)

            # Start the tool execution
            result = await executor.start_execution(
                tool_type=tool,
                command=command,
                environment={"SCAN_ID": scan_id},
                entrypoint=entrypoint,
            )

            if result.get("status") == ExecutionStatus.FAILED:
                error_msg = result.get("error", "Unknown error")
                logger.error(f"Scan {scan_id}: Tool {tool.value} failed to start: {error_msg}")
                _update_scan_status(db, scan_id, "failed", error=f"{tool.value}: {error_msg}")
                return

            execution_id = result.get("execution_id")
            container_id = result.get("container_id")
            execution_ids.append(execution_id)
            container_ids.append(container_id)

            logger.info(
                f"Scan {scan_id}: Tool {tool.value} started, container: {container_id[:12]}"
            )

            # Wait for completion (poll every 10 seconds)
            while True:
                await asyncio.sleep(10)
                status = await executor.get_execution_status(container_id)
                exec_status = status.get("execution_status")

                if exec_status == ExecutionStatus.COMPLETED:
                    logger.info(f"Scan {scan_id}: Tool {tool.value} completed successfully")
                    break
                elif exec_status == ExecutionStatus.FAILED:
                    exit_code = status.get("exit_code", -1)
                    # Security tools often exit with non-zero codes when findings are detected
                    # Check the tool's expected exit codes from config
                    expected_exit_codes = tool_config.get("expected_exit_codes", [0])
                    if exit_code in expected_exit_codes:
                        logger.info(
                            f"Scan {scan_id}: Tool {tool.value} completed with findings (exit {exit_code})"
                        )
                        break
                    logs = status.get("logs", "")[-500:]  # Last 500 chars
                    logger.error(f"Scan {scan_id}: Tool {tool.value} failed (exit {exit_code})")
                    _update_scan_status(
                        db,
                        scan_id,
                        "failed",
                        error=f"{tool.value} failed (exit {exit_code})",
                        execution_ids=execution_ids,
                    )
                    return
                # Still running, continue polling

        # All tools completed successfully - now process reports
        logger.info(f"Scan {scan_id}: All tools completed, triggering report processing")

        # Run report processor to parse findings and link to this scan_id
        try:
            await _process_scan_reports(scan_id, [t.value for t in tools], executor)
            logger.info(f"Scan {scan_id}: Report processing completed")
        except Exception as report_err:
            logger.error(f"Scan {scan_id}: Report processing failed: {report_err}")
            # Still mark scan as completed - reports can be reprocessed

        logger.info(f"Scan {scan_id}: All tools completed successfully")
        _update_scan_status(db, scan_id, "completed", execution_ids=execution_ids)

    except Exception as e:
        logger.error(f"Scan {scan_id} orchestration error: {str(e)}")
        _update_scan_status(db, scan_id, "failed", error=str(e), execution_ids=execution_ids)
    finally:
        db.close()


def _update_scan_status(
    db: Session,
    scan_id: str,
    status: str,
    error: str | None = None,
    execution_ids: list[str] | None = None,
) -> None:
    """Update scan status in the database."""
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            scan.status = status
            if status in ["completed", "failed", "cancelled"]:
                scan.completed_at = datetime.utcnow()
            # Update metadata - need to create new dict to trigger SQLAlchemy change detection
            current_metadata = dict(scan.scan_metadata) if scan.scan_metadata else {}
            if error:
                current_metadata["error"] = error
            if execution_ids:
                current_metadata["execution_ids"] = execution_ids
            scan.scan_metadata = current_metadata
            db.commit()
            logger.info(f"Updated scan {scan_id} status to {status}")
    except Exception as e:
        logger.error(f"Failed to update scan status: {e}")


@router.get("", response_model=ScanListResponse)
@router.get("/", response_model=ScanListResponse)
async def list_scans(
    db: Session = Depends(get_db),
    status: str | None = Query(None, description="Filter by status"),
    tool: str | None = Query(None, description="Filter by tool"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """
    List all scans with optional filters and pagination.

    Retrieves a paginated list of security scans, optionally filtered by status
    or tool. Results are ordered by start time (most recent first).

    Args:
        status: Filter by scan status (pending, running, completed, failed)
        tool: Filter by scanning tool name
        page: Page number (1-indexed)
        page_size: Number of items per page (1-100)

    Returns:
        ScanListResponse: Paginated list of scans with metadata

    Example Request:
        GET /api/scans?status=completed&page=1&page_size=10

    Example Response:
        ```json
        {
            "scans": [
                {
                    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                    "scan_type": "comprehensive",
                    "target": "all",
                    "tool": "multi-tool",
                    "status": "completed",
                    "total_findings": 127,
                    "critical_findings": 5,
                    "high_findings": 23,
                    "medium_findings": 45,
                    "low_findings": 54
                }
            ],
            "total": 1,
            "page": 1,
            "page_size": 10
        }
        ```
    """
    query = db.query(Scan)

    if status:
        query = query.filter(Scan.status == status)

    if tool:
        query = query.filter(Scan.tool == tool)

    total = query.count()

    scans = (
        query.order_by(desc(Scan.started_at)).offset((page - 1) * page_size).limit(page_size).all()
    )

    return ScanListResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=ScanResponse)
@router.post("/", response_model=ScanResponse)
async def create_scan(scan_request: ScanCreate, db: Session = Depends(get_db)):
    """
    Trigger a new security scan.

    Creates a new scan record and queues a background task to execute the scan.
    The scan runs asynchronously using Docker SDK to orchestrate scanning tools.

    Args:
        scan_request: Scan configuration including:
            - profile: Scan profile (quick, comprehensive, compliance-only)
            - provider: Single provider to scan (aws, azure, gcp, kubernetes, iac)
            - tools: Specific tools to run (overrides profile tools)
            - target: Optional specific target to scan
            - severity_filter: Comma-separated severity levels
            - dry_run: If true, preview commands without executing

    Returns:
        ScanResponse: The created scan record with assigned UUID

    Example Request:
        ```json
        {
            "provider": "aws",
            "tools": ["prowler", "scoutsuite"],
            "severity_filter": "critical,high",
            "dry_run": false
        }
        ```

    Example Response:
        ```json
        {
            "scan_id": "550e8400-e29b-41d4-a716-446655440000",
            "scan_type": "custom",
            "target": "aws",
            "tool": "multi-tool",
            "status": "running",
            "started_at": "2024-01-15T10:30:00Z",
            "total_findings": 0
        }
        ```
    """
    # Validate profile exists
    profile_name = scan_request.profile.value
    if profile_name not in SCAN_PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scan profile: {profile_name}. Available: {list(SCAN_PROFILES.keys())}",
        )

    # Validate tools against provider if both specified
    if scan_request.tools and scan_request.provider:
        available_tools = PROVIDER_TOOLS.get(scan_request.provider, [])
        invalid_tools = [t for t in scan_request.tools if t not in available_tools]
        if invalid_tools:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid tools for {scan_request.provider}: {invalid_tools}. "
                f"Available: {available_tools}",
            )

    # Determine which tools to run
    if scan_request.tools:
        tools_to_run = scan_request.tools
        scan_type = "custom"
    else:
        tools_to_run = [t.value for t in SCAN_PROFILES[profile_name]["tools"]]
        scan_type = profile_name

    # Create scan record
    scan = Scan(
        scan_id=uuid4(),
        scan_type=scan_type,
        target=scan_request.target or scan_request.provider or "all",
        tool="multi-tool",
        status="pending" if scan_request.dry_run else "running",
        started_at=datetime.utcnow(),
        scan_metadata={
            "profile": profile_name,
            "provider": scan_request.provider,
            "tools": tools_to_run,
            "dry_run": scan_request.dry_run,
            "severity_filter": scan_request.severity_filter,
        },
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Queue background task to run the scan
    if not scan_request.dry_run:
        # Get database URL from settings
        settings = get_settings()

        def _handle_task_exception(task: asyncio.Task) -> None:
            """Log any unhandled exceptions from the background task."""
            if task.done() and not task.cancelled():
                exc = task.exception()
                if exc:
                    logger.error(f"Scan orchestration task failed: {exc}")

        # Launch async task in background with exception handling
        task = asyncio.create_task(
            run_scan_orchestration(
                str(scan.scan_id),
                profile_name,
                scan_request.severity_filter,
                settings.database_url,
            )
        )
        task.add_done_callback(_handle_task_exception)

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: UUID, db: Session = Depends(get_db)):
    """
    Get details of a specific scan.

    Retrieves complete information about a scan including its status,
    timing information, and finding counts by severity.

    Args:
        scan_id: UUID of the scan to retrieve

    Returns:
        ScanResponse: Complete scan details

    Raises:
        HTTPException 404: If scan is not found
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: UUID, db: Session = Depends(get_db)):
    """
    Get the current status of a scan.

    Returns a lightweight status response for polling scan progress.

    Args:
        scan_id: UUID of the scan

    Returns:
        dict: Scan status with finding counts

    Raises:
        HTTPException 404: If scan is not found
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": str(scan.scan_id),
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings": {
            "total": scan.total_findings,
            "critical": scan.critical_findings,
            "high": scan.high_findings,
            "medium": scan.medium_findings,
            "low": scan.low_findings,
        },
    }


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: UUID, db: Session = Depends(get_db)):
    """
    Cancel a running or pending scan.

    Sets the scan status to 'cancelled' and records the completion time.
    Only scans with status 'pending' or 'running' can be cancelled.

    Args:
        scan_id: UUID of the scan to cancel

    Returns:
        dict: Confirmation message with scan ID

    Raises:
        HTTPException 404: If scan is not found
        HTTPException 400: If scan is not in a cancellable state
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ["pending", "running"]:
        raise HTTPException(
            status_code=400, detail=f"Cannot cancel scan with status: {scan.status}"
        )

    scan.status = "cancelled"
    scan.completed_at = datetime.utcnow()
    db.commit()

    return {"message": "Scan cancelled", "scan_id": str(scan_id)}


@router.get("/profiles/list")
async def list_profiles():
    """
    List available scan profiles.

    Returns metadata about each predefined scan profile including
    name, description, estimated duration, and tools included.

    Available Profiles:
        - quick: Fast scan (5-10 min) focusing on critical/high issues
        - comprehensive: Full audit (30-60 min) with all AWS tools enabled
        - compliance-only: Compliance-focused scanning (15-20 min)

    Returns:
        dict: List of available profiles with descriptions and tool lists
    """
    profiles = []
    for name, config in SCAN_PROFILES.items():
        profiles.append(
            {
                "name": name,
                "description": config.get("description", ""),
                "duration_estimate": config.get("duration_estimate", "Unknown"),
                "tools": [t.value for t in config.get("tools", [])],
            }
        )
    return {"profiles": profiles}


@router.get("/tools")
async def list_all_tools():
    """
    List all available tools grouped by provider.

    Returns a mapping of cloud providers to their available security scanning tools.
    Use this endpoint to discover what tools can be selected for each provider.

    Returns:
        dict: Tools grouped by provider (aws, azure, gcp, kubernetes, iac)

    Example Response:
        ```json
        {
            "tools_by_provider": {
                "aws": ["prowler", "scoutsuite", "cloudsploit", ...],
                "azure": ["prowler", "scoutsuite", "cloudfox"],
                "gcp": ["prowler", "scoutsuite", "cloudfox", "cartography"],
                "kubernetes": ["kube-bench", "kubescape", ...],
                "iac": ["checkov", "terrascan", "tfsec"]
            }
        }
        ```
    """
    return {"tools_by_provider": PROVIDER_TOOLS}


@router.get("/tools/{provider}")
async def get_tools_for_provider(provider: str):
    """
    Get available tools for a specific cloud provider.

    Args:
        provider: Cloud provider name (aws, azure, gcp, kubernetes, iac)

    Returns:
        dict: Provider name and list of available tools

    Raises:
        HTTPException 400: If provider is not recognized

    Example Response:
        ```json
        {
            "provider": "aws",
            "tools": ["prowler", "scoutsuite", "cloudsploit", ...]
        }
        ```
    """
    if provider not in PROVIDER_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider: {provider}. Available providers: {list(PROVIDER_TOOLS.keys())}",
        )
    return {"provider": provider, "tools": PROVIDER_TOOLS[provider]}
