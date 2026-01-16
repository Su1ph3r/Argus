"""
IaC (Infrastructure-as-Code) Security Scanning API Endpoints.

This module provides endpoints for uploading and scanning IaC files including:
- Terraform (.tf, .tfvars)
- CloudFormation (.yaml, .yml, .json with CF templates)
- Kubernetes manifests (.yaml, .yml)
- Helm charts
- ARM templates

Endpoints:
    POST /iac/upload - Upload IaC files for scanning
    POST /iac/scan/{scan_id} - Start IaC scan on uploaded files
    GET /iac/profiles - List available IaC scan profiles
    DELETE /iac/staging/{scan_id} - Cleanup staging area
"""

import asyncio
import logging
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models.database import Scan, get_db
from services.docker_executor import (
    IAC_SCAN_PROFILES,
    TOOL_CONFIGS,
    DockerExecutor,
    ExecutionStatus,
    ToolType,
    get_docker_executor,
)

router: APIRouter = APIRouter(prefix="/iac", tags=["IaC Scanning"])
logger: logging.Logger = logging.getLogger(__name__)

# Upload limits
MAX_FILE_SIZE_MB = 50
MAX_TOTAL_SIZE_MB = 200
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_TOTAL_SIZE_BYTES = MAX_TOTAL_SIZE_MB * 1024 * 1024

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    ".tf", ".tfvars", ".hcl",  # Terraform
    ".yaml", ".yml",  # Kubernetes/CloudFormation/Helm
    ".json",  # CloudFormation/Kubernetes
    ".tpl",  # Helm templates
    ".zip",  # Archives
}

# IaC staging directory (inside the container)
IAC_STAGING_BASE = Path("/app/iac-staging")

# Maximum time to wait for a single tool to complete (1 hour for IaC is more than enough)
MAX_TOOL_TIMEOUT_SECONDS = 60 * 60
# Polling interval in seconds
POLL_INTERVAL_SECONDS = 5

# Concurrency limits for upload endpoint (prevents resource exhaustion)
MAX_CONCURRENT_UPLOADS = 5
_upload_semaphore = asyncio.Semaphore(MAX_CONCURRENT_UPLOADS)


# ============================================================================
# Pydantic Models
# ============================================================================


class IaCUploadResponse(BaseModel):
    """Response from IaC file upload."""

    scan_id: str = Field(description="Unique scan ID for the uploaded files")
    files_uploaded: int = Field(description="Number of files uploaded")
    total_size_bytes: int = Field(description="Total size of uploaded files")
    message: str = Field(description="Status message")


class IaCProfile(BaseModel):
    """IaC scan profile details."""

    name: str
    description: str
    tools: list[str]
    duration_estimate: str
    supported_frameworks: list[str]


class IaCProfilesResponse(BaseModel):
    """Response listing available IaC scan profiles."""

    profiles: list[IaCProfile]


class IaCScanStartResponse(BaseModel):
    """Response from starting an IaC scan."""

    scan_id: str
    status: str
    message: str
    profile: str
    tools: list[str]


class IaCStagingDeleteResponse(BaseModel):
    """Response from deleting IaC staging files."""

    scan_id: str
    deleted: bool
    message: str


# ============================================================================
# Helper Functions
# ============================================================================


def _validate_file_extension(filename: str) -> bool:
    """Validate that the file has an allowed extension."""
    if not filename:
        return False
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def _is_path_safe(base_path: Path, target_path: Path) -> bool:
    """
    Verify that target_path is safely within base_path (no path traversal).

    This is critical for preventing zip-slip attacks where malicious archives
    contain entries like "../../../etc/passwd".
    """
    try:
        # Resolve both paths to absolute paths
        resolved_base = base_path.resolve()
        resolved_target = target_path.resolve()
        # Check that target is under base
        return str(resolved_target).startswith(str(resolved_base) + os.sep) or resolved_target == resolved_base
    except (OSError, ValueError):
        return False


def _extract_zip_safely(zip_path: Path, extract_to: Path) -> int:
    """
    Safely extract a zip file with path traversal and zip bomb protection.

    Returns the number of files extracted.
    Raises HTTPException if zip contents exceed size limits.
    """
    extracted_count = 0
    total_uncompressed_size = 0

    with zipfile.ZipFile(zip_path, 'r') as zf:
        # First pass: check total uncompressed size (zip bomb protection)
        for info in zf.infolist():
            if not info.is_dir():
                # Check individual file size
                if info.file_size > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File in zip exceeds maximum size: {info.filename}"
                    )
                total_uncompressed_size += info.file_size

        # Check total uncompressed size
        if total_uncompressed_size > MAX_TOTAL_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"Zip contents exceed maximum total size of {MAX_TOTAL_SIZE_MB}MB"
            )

        # Second pass: extract files
        for member in zf.namelist():
            # Skip directories
            if member.endswith('/'):
                continue

            # Construct the target path
            member_path = extract_to / member

            # Validate path safety (zip-slip protection)
            if not _is_path_safe(extract_to, member_path):
                logger.warning(f"Skipping potentially unsafe path in zip: {member}")
                continue

            # Check file extension
            if not _validate_file_extension(member):
                logger.debug(f"Skipping unsupported file type in zip: {member}")
                continue

            # Create parent directories
            member_path.parent.mkdir(parents=True, exist_ok=True)

            # Extract file
            with zf.open(member) as src, open(member_path, 'wb') as dst:
                dst.write(src.read())
            extracted_count += 1

    return extracted_count


def _validate_scan_id(scan_id: str) -> str:
    """
    Validate that scan_id is a valid UUID format.

    Raises HTTPException if invalid.
    Returns the validated scan_id string.
    """
    try:
        # Validate UUID format (version 4)
        UUID(scan_id, version=4)
        return scan_id
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid scan_id format. Must be a valid UUID."
        )


def _get_staging_path(scan_id: str) -> Path:
    """Get the staging path for a scan."""
    return IAC_STAGING_BASE / scan_id


def _update_scan_status(
    db: Session,
    scan_id: str,
    status: str,
    error: str | None = None,
    tool_errors: dict[str, str] | None = None,
    completed_tools: list[str] | None = None,
) -> None:
    """Update scan status in the database."""
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            scan.status = status
            if status == "completed":
                scan.completed_at = datetime.utcnow()
            if error:
                metadata = scan.scan_metadata or {}
                metadata["error"] = error
                if tool_errors:
                    metadata["tool_errors"] = tool_errors
                if completed_tools:
                    metadata["completed_tools"] = completed_tools
                scan.scan_metadata = metadata
            db.commit()
    except Exception as e:
        logger.error(f"Failed to update scan status: {e}")
        db.rollback()


def _sanitize_log_snippet(log_text: str) -> str:
    """Remove sensitive information from log snippets."""
    import re

    if not log_text:
        return ""

    max_len = 500
    if len(log_text) > max_len:
        log_text = log_text[:max_len] + "...[truncated]"

    # Redact file paths that might contain usernames
    log_text = re.sub(r"/[a-zA-Z0-9_.\-]+(?:/[a-zA-Z0-9_.\-]+){2,}", "/...[PATH]", log_text)

    return log_text


async def _process_iac_reports(scan_id: str, tools: list[str]) -> None:
    """
    Process IaC scan reports and store findings in the database.

    This is called after all IaC tools complete.
    """
    import sys
    sys.path.insert(0, "/app/report-processor")

    try:
        from process_reports import ReportProcessor

        processor = ReportProcessor()
        processor.process_for_scan(scan_id, tools)
        logger.info(f"IaC report processing completed for scan {scan_id}")
    except ImportError as e:
        logger.error(f"Could not import ReportProcessor: {e}")
    except Exception as e:
        logger.error(f"IaC report processing failed: {e}")


async def run_iac_scan_orchestration(
    scan_id: str,
    profile: str,
    db_url: str,
    staging_path: str,
) -> None:
    """
    Background task to orchestrate an IaC security scan.

    Launches IaC scanning tools based on the profile, waiting for each
    to complete before starting the next.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # Create a new database session for background task
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        executor = get_docker_executor()
        profile_config = IAC_SCAN_PROFILES.get(profile)

        if not profile_config:
            logger.error(f"Unknown IaC scan profile: {profile}")
            _update_scan_status(db, scan_id, "failed", error="Unknown IaC profile")
            return

        tools: list[ToolType] = profile_config["tools"]
        tool_errors: dict[str, str] = {}
        completed_tools: list[str] = []

        logger.info(
            f"Starting IaC scan {scan_id} with profile '{profile}', tools: {[t.value for t in tools]}"
        )
        # Resolve the host path for staging
        # The staging path is at /app/iac-staging/{scan_id} in the container
        # We need to map it to the host path for Docker volume mounts
        host_project_path = os.environ.get("HOST_PROJECT_PATH", "").strip()
        if not host_project_path:
            logger.error("HOST_PROJECT_PATH not set, cannot mount staging directory")
            _update_scan_status(db, scan_id, "failed", error="HOST_PROJECT_PATH not configured")
            db.close()
            return

        host_staging_path = os.path.join(host_project_path, "iac-staging", scan_id)

        for tool in tools:
            logger.info(f"IaC Scan {scan_id}: Starting tool {tool.value}")

            # Get tool config
            tool_config = TOOL_CONFIGS.get(tool, {})

            # Build extra volumes to mount the scan-specific staging directory
            extra_volumes = {}

            # Determine the container mount point based on tool
            if tool == ToolType.CHECKOV:
                container_mount = "/code"
            elif tool == ToolType.TERRASCAN:
                container_mount = "/iac"
            elif tool == ToolType.TFSEC:
                container_mount = "/src"
            elif tool in (ToolType.KUBE_LINTER, ToolType.POLARIS):
                container_mount = "/manifests"
            else:
                container_mount = "/code"

            # Override the default staging volume with scan-specific path
            extra_volumes[host_staging_path] = {"bind": container_mount, "mode": "ro"}

            # Build command based on tool
            command = None
            entrypoint = tool_config.get("entrypoint")

            if tool == ToolType.CHECKOV:
                command = [
                    "-d", "/code",
                    "--output", "json",
                    "--output-file-path", "/reports",
                    "--framework", "terraform", "cloudformation", "kubernetes", "helm", "arm",
                    "--quiet",
                ]
            elif tool == ToolType.TERRASCAN:
                command = [
                    "scan",
                    "-d", "/iac",
                    "-o", "json",
                ]
            elif tool == ToolType.TFSEC:
                command = [
                    "/src",
                    "--format", "json",
                    "--out", f"/reports/tfsec-{scan_id}.json",
                    "--soft-fail",
                ]
            elif tool == ToolType.KUBE_LINTER:
                command = [
                    "lint",
                    "/manifests",
                    "--format", "json",
                ]
            elif tool == ToolType.POLARIS:
                command = [
                    "audit",
                    "--audit-path", "/manifests",
                    "--format", "json",
                    "--output-file", f"/reports/polaris-{scan_id}.json",
                ]
            else:
                default_cmd = tool_config.get("default_command", [])
                if default_cmd:
                    command = list(default_cmd)

            # Environment for IaC tools (no AWS credentials needed)
            env = {"SCAN_ID": scan_id}

            # Start the tool execution
            result = await executor.start_execution(
                tool_type=tool,
                command=command,
                environment=env,
                extra_volumes=extra_volumes,
                entrypoint=entrypoint,
            )

            if result.get("status") == ExecutionStatus.FAILED:
                error_msg = result.get("error", "Unknown error")
                tool_errors[tool.value] = f"Failed to start: {error_msg}"
                logger.error(f"IaC Scan {scan_id}: Tool {tool.value} failed to start: {error_msg}")
                _update_scan_status(
                    db, scan_id, "failed",
                    error=f"{tool.value}: {error_msg}",
                    tool_errors=tool_errors,
                    completed_tools=completed_tools,
                )
                db.close()
                return

            container_id = result.get("container_id")
            if not container_id:
                tool_errors[tool.value] = "No container ID returned"
                logger.error(f"IaC Scan {scan_id}: Tool {tool.value} - no container ID returned")
                continue

            logger.info(
                f"IaC Scan {scan_id}: Tool {tool.value} started, container: {container_id[:12]}"
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
                    logger.info(f"IaC Scan {scan_id}: Tool {tool.value} completed successfully")
                    # Cleanup container
                    await executor.cleanup_container(container_id)
                    break
                elif exec_status == ExecutionStatus.FAILED:
                    exit_code = status.get("exit_code", -1)
                    expected_exit_codes = tool_config.get("expected_exit_codes", [0])

                    if exit_code in expected_exit_codes:
                        completed_tools.append(tool.value)
                        logger.info(
                            f"IaC Scan {scan_id}: Tool {tool.value} completed with findings (exit {exit_code})"
                        )
                        await executor.cleanup_container(container_id)
                        break

                    logs = status.get("logs", "")[-500:]
                    log_snippet = _sanitize_log_snippet(logs[-200:].strip()) if logs else ""
                    tool_errors[tool.value] = f"Exit code {exit_code}: {log_snippet}" if log_snippet else f"Exit code {exit_code}"
                    logger.error(f"IaC Scan {scan_id}: Tool {tool.value} failed (exit {exit_code})")
                    await executor.cleanup_container(container_id)
                    # Continue with other tools instead of failing the whole scan
                    break

            else:
                # Timeout reached
                tool_errors[tool.value] = "Timeout"
                logger.error(f"IaC Scan {scan_id}: Tool {tool.value} timed out")
                await executor.stop_execution(container_id)
                await executor.cleanup_container(container_id)

        # All tools finished (some may have failed)
        if completed_tools:
            # Process reports for successfully completed tools
            logger.info(f"IaC Scan {scan_id}: Processing reports for completed tools: {completed_tools}")
            await _process_iac_reports(scan_id, completed_tools)

            if tool_errors:
                # Partial success
                _update_scan_status(
                    db, scan_id, "completed",
                    tool_errors=tool_errors,
                    completed_tools=completed_tools,
                )
            else:
                # Full success
                _update_scan_status(db, scan_id, "completed", completed_tools=completed_tools)
        else:
            # All tools failed
            _update_scan_status(
                db, scan_id, "failed",
                error="All IaC scanning tools failed",
                tool_errors=tool_errors,
            )

    except Exception as e:
        logger.exception(f"IaC Scan {scan_id} orchestration failed: {e}")
        # Store sanitized error message (no internal paths or stack traces)
        _update_scan_status(db, scan_id, "failed", error="Scan orchestration failed unexpectedly")
    finally:
        db.close()

        # Cleanup staging directory after scan completes
        try:
            cleanup_path = _get_staging_path(scan_id)
            if cleanup_path.exists():
                shutil.rmtree(cleanup_path)
                logger.info(f"Cleaned up staging directory for scan {scan_id}")
        except Exception as cleanup_error:
            logger.warning(f"Failed to cleanup staging directory: {cleanup_error}")


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/profiles", response_model=IaCProfilesResponse)
async def list_iac_profiles():
    """
    List available IaC scan profiles.

    Returns all configured IaC scanning profiles with their tools and descriptions.
    """
    profiles = []
    for name, config in IAC_SCAN_PROFILES.items():
        profiles.append(IaCProfile(
            name=name,
            description=config.get("description", ""),
            tools=[t.value for t in config.get("tools", [])],
            duration_estimate=config.get("duration_estimate", "Unknown"),
            supported_frameworks=config.get("supported_frameworks", []),
        ))

    return IaCProfilesResponse(profiles=profiles)


@router.post("/upload", response_model=IaCUploadResponse)
async def upload_iac_files(
    files: list[UploadFile] = File(..., description="IaC files to upload"),
):
    """
    Upload IaC files for security scanning.

    Accepts Terraform, CloudFormation, Kubernetes manifests, Helm charts, and ARM templates.
    Files can be uploaded individually or as a .zip archive.

    Limits:
    - Maximum 50MB per file
    - Maximum 200MB total
    - Maximum 5 concurrent uploads
    - Allowed extensions: .tf, .tfvars, .hcl, .yaml, .yml, .json, .tpl, .zip
    """
    # Acquire semaphore to limit concurrent uploads (prevents resource exhaustion)
    async with _upload_semaphore:
        # Generate a unique scan ID for this upload
        scan_id = str(uuid4())
        staging_path = _get_staging_path(scan_id)

        # Create staging directory
        staging_path.mkdir(parents=True, exist_ok=True)

        try:
            total_size = 0
            files_uploaded = 0

            for upload_file in files:
                # Validate filename
                if not upload_file.filename:
                    continue

                # Validate extension
                if not _validate_file_extension(upload_file.filename):
                    logger.warning(f"Skipping file with unsupported extension: {upload_file.filename}")
                    continue

                # Read file content
                content = await upload_file.read()
                file_size = len(content)

                # Check individual file size
                if file_size > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File {upload_file.filename} exceeds maximum size of {MAX_FILE_SIZE_MB}MB"
                    )

                # Check total size
                total_size += file_size
                if total_size > MAX_TOTAL_SIZE_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Total upload size exceeds maximum of {MAX_TOTAL_SIZE_MB}MB"
                    )

                # Handle zip files
                if upload_file.filename.lower().endswith('.zip'):
                    # Write zip to temp location
                    zip_path = staging_path / upload_file.filename
                    with open(zip_path, 'wb') as f:
                        f.write(content)

                    # Extract safely
                    try:
                        extracted = _extract_zip_safely(zip_path, staging_path)
                        files_uploaded += extracted
                        logger.info(f"Extracted {extracted} files from {upload_file.filename}")
                    except zipfile.BadZipFile:
                        raise HTTPException(status_code=400, detail=f"Invalid zip file: {upload_file.filename}")
                    finally:
                        # Remove the zip file after extraction
                        zip_path.unlink(missing_ok=True)
                else:
                    # Regular file - write directly
                    # Sanitize filename to prevent path traversal
                    safe_filename = Path(upload_file.filename).name
                    file_path = staging_path / safe_filename

                    # Validate path safety
                    if not _is_path_safe(staging_path, file_path):
                        logger.warning(f"Skipping unsafe filename: {upload_file.filename}")
                        continue

                    with open(file_path, 'wb') as f:
                        f.write(content)
                    files_uploaded += 1

            if files_uploaded == 0:
                # Cleanup empty staging directory
                shutil.rmtree(staging_path, ignore_errors=True)
                raise HTTPException(
                    status_code=400,
                    detail="No valid IaC files found in upload. Supported extensions: " + ", ".join(ALLOWED_EXTENSIONS)
                )

            return IaCUploadResponse(
                scan_id=scan_id,
                files_uploaded=files_uploaded,
                total_size_bytes=total_size,
                message=f"Successfully uploaded {files_uploaded} file(s) for scanning",
            )

        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            # Cleanup on error
            shutil.rmtree(staging_path, ignore_errors=True)
            logger.exception(f"Failed to process IaC upload: {e}")
            # Return generic error message to client (no internal details)
            raise HTTPException(status_code=500, detail="Failed to process upload. Please try again.")


@router.post("/scan/{scan_id}", response_model=IaCScanStartResponse)
async def start_iac_scan(
    scan_id: str,
    profile: str = Query(default="iac-quick", description="IaC scan profile to use"),
    db: Session = Depends(get_db),
):
    """
    Start an IaC security scan on previously uploaded files.

    The scan_id should be from a previous /iac/upload call.

    Available profiles:
    - iac-quick: Checkov only (fast)
    - iac-comprehensive: Checkov + Terrascan + tfsec (thorough)
    - kubernetes-manifests: kube-linter + Polaris (K8s focused)
    """
    from config import get_settings

    # Validate scan_id format
    _validate_scan_id(scan_id)

    # Validate profile
    if profile not in IAC_SCAN_PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown profile: {profile}. Available profiles: {list(IAC_SCAN_PROFILES.keys())}"
        )

    # Check staging directory exists
    staging_path = _get_staging_path(scan_id)
    if not staging_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No uploaded files found for scan_id: {scan_id}. Please upload files first via /iac/upload"
        )

    # Check for at least one file
    files_in_staging = list(staging_path.glob("**/*"))
    iac_files = [f for f in files_in_staging if f.is_file() and _validate_file_extension(f.name)]
    if not iac_files:
        raise HTTPException(
            status_code=400,
            detail="No valid IaC files found in staging directory"
        )

    # Get profile config
    profile_config = IAC_SCAN_PROFILES[profile]
    tools = [t.value for t in profile_config["tools"]]

    # Create scan record in database
    try:
        new_scan = Scan(
            scan_id=scan_id,
            scan_type="iac",
            tool=",".join(tools),
            target="iac-upload",
            status="running",
            started_at=datetime.utcnow(),
            scan_metadata={
                "profile": profile,
                "tools": tools,
                "files_count": len(iac_files),
                "scan_type": "iac",
            }
        )
        db.add(new_scan)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to create scan record: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create scan record")

    # Get database URL for background task
    settings = get_settings()
    db_url = settings.database_url

    # Start background scan orchestration
    asyncio.create_task(
        run_iac_scan_orchestration(
            scan_id=scan_id,
            profile=profile,
            db_url=db_url,
            staging_path=str(staging_path),
        )
    )

    return IaCScanStartResponse(
        scan_id=scan_id,
        status="running",
        message=f"IaC scan started with profile '{profile}'",
        profile=profile,
        tools=tools,
    )


@router.delete("/staging/{scan_id}", response_model=IaCStagingDeleteResponse)
async def delete_iac_staging(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """
    Delete IaC staging files for a scan.

    Use this to cleanup uploaded files if you don't want to run a scan,
    or to manually cleanup after a scan completes.

    Returns HTTP 409 Conflict if a scan is currently running for this scan_id.
    """
    # Validate scan_id format to prevent path traversal
    _validate_scan_id(scan_id)

    # Check if a scan is currently running for this scan_id (race condition prevention)
    existing_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if existing_scan and existing_scan.status == "running":
        raise HTTPException(
            status_code=409,
            detail="Cannot delete staging files while scan is running. Wait for scan to complete or cancel it first."
        )

    staging_path = _get_staging_path(scan_id)

    if not staging_path.exists():
        return IaCStagingDeleteResponse(
            scan_id=scan_id,
            deleted=False,
            message="Staging directory not found (may have already been cleaned up)"
        )

    try:
        shutil.rmtree(staging_path)
        return IaCStagingDeleteResponse(
            scan_id=scan_id,
            deleted=True,
            message="Staging directory deleted successfully"
        )
    except Exception as e:
        logger.error(f"Failed to delete staging directory: {e}")
        # Return generic error message to client (no internal details)
        raise HTTPException(status_code=500, detail="Failed to delete staging directory")
