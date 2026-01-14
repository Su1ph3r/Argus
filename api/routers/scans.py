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
import re
from datetime import datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from config import get_settings
from models.database import Scan, ScanFile, get_db
from models.schemas import (
    ArchiveInfo,
    ArchiveListResponse,
    BulkArchiveRequest,
    BulkArchiveResponse,
    BulkDeleteRequest,
    BulkDeleteResponse,
    ScanCreate,
    ScanFileResponse,
    ScanListResponse,
    ScanResponse,
)
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

# Maximum time to wait for a single tool to complete (6 hours)
MAX_TOOL_TIMEOUT_SECONDS = 6 * 60 * 60
# Polling interval in seconds
POLL_INTERVAL_SECONDS = 10

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


def _sanitize_log_snippet(log_text: str) -> str:
    """Remove sensitive information from log snippets before storage.

    Redacts credentials, tokens, file paths, and IP addresses to prevent
    information leakage through error messages exposed via the API.
    """
    if not log_text:
        return ""

    # Redact AWS access keys (AKIA...)
    log_text = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]", log_text)

    # Redact AWS secret keys and session tokens in various formats
    log_text = re.sub(
        r"(aws_secret_access_key|secret_access_key|aws_session_token)[:\s=]+[^\s]+",
        r"\1=[REDACTED]",
        log_text,
        flags=re.IGNORECASE,
    )

    # Redact generic secret/token patterns
    log_text = re.sub(
        r"(secret|token|password|api_key|apikey)[:\s=]+[^\s]+",
        r"\1=[REDACTED]",
        log_text,
        flags=re.IGNORECASE,
    )

    # Redact IP addresses
    log_text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]", log_text)

    # Redact potential tokens/keys (long alphanumeric strings 40+ chars)
    log_text = re.sub(r"[a-zA-Z0-9+/]{40,}", "[TOKEN]", log_text)

    # Redact file paths that might expose system info (keep basename for context)
    log_text = re.sub(r"/(?:[a-zA-Z0-9_\-\.]+/){2,}([a-zA-Z0-9_\-\.]+)", r"/...//\1", log_text)

    return log_text


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

    # Use direct processing - the API container has reports mounted at /reports
    # and report-processor code at /app/report-processor, so we can process
    # directly without spawning a separate container (avoids Windows path issues)
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



def _replace_profile_in_command(command: list[str], aws_profile: str, tool: "ToolType") -> list[str]:
    """
    Replace hardcoded AWS profile references in command arguments with the dynamic profile.
    
    Different tools use different flags:
    - Prowler: --profile <name>
    - ScoutSuite: --profile <name>
    - CloudFox: --profile <name>
    - Others: may use --profile or AWS_PROFILE env var
    """
    result = []
    skip_next = False
    profile_added = False
    
    for i, arg in enumerate(command):
        if skip_next:
            # This is the profile value following --profile, replace it
            result.append(aws_profile)
            skip_next = False
            profile_added = True
        elif arg == "--profile":
            result.append(arg)
            skip_next = True  # Next arg is the profile value to replace
        elif arg.startswith("--profile="):
            # Handle --profile=value format
            result.append(f"--profile={aws_profile}")
            profile_added = True
        else:
            result.append(arg)
    
    # If no --profile flag was found in command, some tools need it added
    # The environment variable AWS_PROFILE should handle most cases
    # but for tools that require the CLI flag, we add it
    if not profile_added and tool.value in ("prowler", "scoutsuite", "cloudfox"):
        # Insert --profile after the subcommand (usually first or second arg)
        if len(result) >= 1:
            # For prowler: aws --profile <name> ...
            # For scoutsuite: --provider aws --profile <name> ...
            # For cloudfox: aws all-checks --profile <name> ...
            result.extend(["--profile", aws_profile])
    
    return result


async def run_scan_orchestration(
    scan_id: str,
    profile: str,
    severity_filter: str | None,
    db_url: str,
    aws_profile: str | None = None,
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
    tool_errors: dict[str, str] = {}  # Track per-tool errors
    completed_tools: list[str] = []  # Track successfully completed tools

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

            # Build environment with dynamic AWS profile
            env = {"SCAN_ID": scan_id}
            if aws_profile:
                env["AWS_PROFILE"] = aws_profile
                # Also replace hardcoded profile in command if present
                if command:
                    command = _replace_profile_in_command(command, aws_profile, tool)

            # Start the tool execution
            result = await executor.start_execution(
                tool_type=tool,
                command=command,
                environment=env,
                entrypoint=entrypoint,
            )

            if result.get("status") == ExecutionStatus.FAILED:
                error_msg = result.get("error", "Unknown error")
                tool_errors[tool.value] = f"Failed to start: {error_msg}"
                logger.error(f"Scan {scan_id}: Tool {tool.value} failed to start: {error_msg}")
                _update_scan_status(
                    db, scan_id, "failed",
                    error=f"{tool.value}: {error_msg}",
                    tool_errors=tool_errors,
                    completed_tools=completed_tools,
                )
                return

            execution_id = result.get("execution_id")
            container_id = result.get("container_id")
            execution_ids.append(execution_id)
            container_ids.append(container_id)

            logger.info(
                f"Scan {scan_id}: Tool {tool.value} started, container: {container_id[:12]}"
            )

            # Wait for completion with timeout
            elapsed_seconds = 0
            while elapsed_seconds < MAX_TOOL_TIMEOUT_SECONDS:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                elapsed_seconds += POLL_INTERVAL_SECONDS
                status = await executor.get_execution_status(container_id)
                exec_status = status.get("execution_status")

                if exec_status == ExecutionStatus.COMPLETED:
                    completed_tools.append(tool.value)
                    logger.info(f"Scan {scan_id}: Tool {tool.value} completed successfully")
                    break
                elif exec_status == ExecutionStatus.FAILED:
                    exit_code = status.get("exit_code", -1)
                    # Security tools often exit with non-zero codes when findings are detected
                    # Check the tool's expected exit codes from config
                    expected_exit_codes = tool_config.get("expected_exit_codes", [0])
                    if exit_code in expected_exit_codes:
                        completed_tools.append(tool.value)
                        logger.info(
                            f"Scan {scan_id}: Tool {tool.value} completed with findings (exit {exit_code})"
                        )
                        break
                    logs = status.get("logs", "")[-500:]  # Last 500 chars
                    # Extract meaningful error from logs (last 200 chars)
                    log_snippet = _sanitize_log_snippet(logs[-200:].strip()) if logs else ""
                    tool_errors[tool.value] = f"Exit code {exit_code}: {log_snippet}" if log_snippet else f"Exit code {exit_code}"
                    logger.error(f"Scan {scan_id}: Tool {tool.value} failed (exit {exit_code})")
                    _update_scan_status(
                        db,
                        scan_id,
                        "failed",
                        error=f"{tool.value} failed (exit {exit_code})",
                        execution_ids=execution_ids,
                        tool_errors=tool_errors,
                        completed_tools=completed_tools,
                    )
                    return
                elif exec_status == ExecutionStatus.PENDING:
                    # Container in unexpected state (paused, dead, created, etc.)
                    container_status = status.get("status", "unknown")
                    if container_status in ("paused", "dead", "removing"):
                        tool_errors[tool.value] = f"Container {container_status}"
                        logger.error(
                            f"Scan {scan_id}: Tool {tool.value} container in bad state: {container_status}"
                        )
                        _update_scan_status(
                            db,
                            scan_id,
                            "failed",
                            error=f"{tool.value} container {container_status}",
                            execution_ids=execution_ids,
                            tool_errors=tool_errors,
                            completed_tools=completed_tools,
                        )
                        return
                    # "created" or other states - continue polling but log warning
                    if elapsed_seconds % 60 == 0:  # Log every minute
                        logger.warning(
                            f"Scan {scan_id}: Tool {tool.value} still pending ({container_status}), "
                            f"waited {elapsed_seconds}s"
                        )
                # RUNNING status - continue polling
            else:
                # Loop completed without break - timeout reached
                timeout_hours = MAX_TOOL_TIMEOUT_SECONDS // 3600
                tool_errors[tool.value] = f"Timed out after {timeout_hours}h"
                logger.error(
                    f"Scan {scan_id}: Tool {tool.value} timed out after {MAX_TOOL_TIMEOUT_SECONDS}s"
                )
                _update_scan_status(
                    db,
                    scan_id,
                    "failed",
                    error=f"{tool.value} timed out after {timeout_hours}h",
                    execution_ids=execution_ids,
                    tool_errors=tool_errors,
                    completed_tools=completed_tools,
                )
                return

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
        _update_scan_status(
            db, scan_id, "completed",
            execution_ids=execution_ids,
            tool_errors=tool_errors,  # Empty dict if all succeeded
            completed_tools=completed_tools,
        )

    except Exception as e:
        logger.error(f"Scan {scan_id} orchestration error: {str(e)}")
        _update_scan_status(
            db, scan_id, "failed",
            error=str(e),
            execution_ids=execution_ids,
            tool_errors=tool_errors,
            completed_tools=completed_tools,
        )
    finally:
        db.close()


def _update_scan_status(
    db: Session,
    scan_id: str,
    status: str,
    error: str | None = None,
    execution_ids: list[str] | None = None,
    tool_errors: dict[str, str] | None = None,
    completed_tools: list[str] | None = None,
) -> None:
    """Update scan status in the database with per-tool error tracking."""
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
            if tool_errors is not None:
                current_metadata["tool_errors"] = tool_errors
            if completed_tools is not None:
                current_metadata["completed_tools"] = completed_tools
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
                scan_request.aws_profile,
            )
        )
        task.add_done_callback(_handle_task_exception)

    return ScanResponse.model_validate(scan)


# ============================================================================
# Static Routes (must be defined BEFORE dynamic {scan_id} routes)
# ============================================================================


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


@router.get("/archives", response_model=ArchiveListResponse)
async def list_archives():
    """
    List all available scan archives.

    Returns:
        ArchiveListResponse: List of archives with metadata
    """
    from services.archive_service import get_archive_service

    archive_service = get_archive_service()
    archives = archive_service.list_archives()

    return ArchiveListResponse(
        archives=[ArchiveInfo(**a) for a in archives],
        total=len(archives),
    )


@router.delete("/bulk", response_model=BulkDeleteResponse)
async def bulk_delete_scans(
    request: BulkDeleteRequest,
    db: Session = Depends(get_db),
):
    """
    Delete multiple scans and optionally their associated files.

    Only scans with status completed/failed/cancelled can be deleted.
    Running scans will be skipped with a warning in the response.

    Args:
        request: BulkDeleteRequest with scan_ids list and delete_files flag

    Returns:
        BulkDeleteResponse: Summary of deletion operation
    """
    from services.archive_service import get_archive_service

    deleted_scans = 0
    deleted_files = 0
    skipped_scans = []
    errors = []

    archive_service = get_archive_service()

    for scan_id in request.scan_ids:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

        if not scan:
            errors.append(f"{scan_id}: Scan not found")
            continue

        # Skip running scans
        if scan.status in ["pending", "running"]:
            skipped_scans.append(str(scan_id))
            continue

        # Get associated files if we need to delete them
        if request.delete_files:
            scan_files = db.query(ScanFile).filter(ScanFile.scan_id == scan_id).all()
            file_paths = [sf.file_path for sf in scan_files]

            if file_paths:
                count, file_errors = archive_service.delete_files(file_paths)
                deleted_files += count
                errors.extend(file_errors)

        # Delete the scan (cascade will delete ScanFile records)
        try:
            db.delete(scan)
            db.commit()
            deleted_scans += 1
        except Exception as e:
            db.rollback()
            errors.append(f"{scan_id}: Failed to delete - {str(e)}")

    return BulkDeleteResponse(
        success=len(errors) == 0 and len(skipped_scans) == 0,
        deleted_scans=deleted_scans,
        deleted_files=deleted_files,
        skipped_scans=skipped_scans,
        errors=errors,
    )


@router.post("/bulk/archive", response_model=BulkArchiveResponse)
async def bulk_archive_scans(
    request: BulkArchiveRequest,
    db: Session = Depends(get_db),
):
    """
    Archive multiple scans into a zip file and delete originals.

    Creates a zip archive containing all report files associated with the
    specified scans, then deletes the original files and database records.

    Archive naming: {YYYYMMDD}_{HHMMSS}_{profile}.zip
    Archives stored in /reports/archives/

    Args:
        request: BulkArchiveRequest with scan_ids list

    Returns:
        BulkArchiveResponse: Archive creation summary

    Raises:
        HTTPException 400: If no valid scans to archive or archive creation fails
    """
    from services.archive_service import get_archive_service

    archive_service = get_archive_service()

    # Collect all file paths and determine profile name
    all_file_paths = []
    profiles = set()
    valid_scan_ids = []

    for scan_id in request.scan_ids:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

        if not scan:
            continue

        # Skip running scans
        if scan.status in ["pending", "running"]:
            continue

        valid_scan_ids.append(scan_id)
        profiles.add(scan.scan_type or "unknown")

        # Get associated files
        scan_files = db.query(ScanFile).filter(ScanFile.scan_id == scan_id).all()
        all_file_paths.extend([sf.file_path for sf in scan_files])

    if not valid_scan_ids:
        raise HTTPException(
            status_code=400,
            detail="No valid scans to archive (must be completed/failed/cancelled)",
        )

    # Determine profile name for archive
    if len(profiles) == 1:
        profile_name = profiles.pop()
    else:
        profile_name = "mixed"

    # Create archive
    try:
        archive_path, archive_size = archive_service.create_archive(profile_name, all_file_paths)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Archive creation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to create archive")

    # Delete original files
    if all_file_paths:
        archive_service.delete_files(all_file_paths)

    # Delete scans from database (cascade handles ScanFile records)
    for scan_id in valid_scan_ids:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            db.delete(scan)

    db.commit()

    archive_name = archive_path.split("/")[-1]

    return BulkArchiveResponse(
        success=True,
        archive_path=archive_path,
        archive_name=archive_name,
        archived_scans=len(valid_scan_ids),
        archived_files=len(all_file_paths),
        archive_size_bytes=archive_size,
    )


# ============================================================================
# Dynamic Routes (with {scan_id} path parameter)
# ============================================================================


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


@router.get("/{scan_id}/errors")
async def get_scan_errors(scan_id: UUID, db: Session = Depends(get_db)):
    """
    Get detailed error information for a scan.

    Returns per-tool error details including which tools succeeded,
    which failed, and specific error messages for debugging.

    Args:
        scan_id: UUID of the scan

    Returns:
        dict: Error breakdown with per-tool status

    Raises:
        HTTPException 404: If scan is not found
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    metadata = scan.scan_metadata or {}

    return {
        "scan_id": str(scan.scan_id),
        "status": scan.status,
        "error": metadata.get("error"),
        "tool_errors": metadata.get("tool_errors", {}),
        "completed_tools": metadata.get("completed_tools", []),
        "profile": metadata.get("profile"),
        "tools_planned": metadata.get("tools", []),
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


@router.get("/{scan_id}/files", response_model=list[ScanFileResponse])
async def get_scan_files(scan_id: UUID, db: Session = Depends(get_db)):
    """
    Get list of files associated with a scan.

    Args:
        scan_id: UUID of the scan

    Returns:
        list[ScanFileResponse]: List of file records

    Raises:
        HTTPException 404: If scan is not found
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    files = db.query(ScanFile).filter(ScanFile.scan_id == scan_id).all()

    return [ScanFileResponse.model_validate(f) for f in files]
