"""PoC Validation API Endpoints.

This module provides endpoints for validating attack paths and privilege
escalation paths using safe read-only commands. The validation engine
ensures that only safe, non-destructive commands are executed.

Endpoints:
    POST /poc-validation/attack-paths/{path_id}/validate - Validate an attack path
    POST /poc-validation/privesc-paths/{path_id}/validate - Validate a privesc path
    POST /poc-validation/batch-validate - Batch validate multiple paths
    GET /poc-validation/status/{validation_id} - Get validation status
    GET /poc-validation/history - Get validation history
    GET /poc-validation/check-command - Check if a command is safe

Security:
    - Only executes commands from strict allowlist (describe/list/get)
    - Blocks all write/modify/delete operations
    - All execution uses subprocess with shell=False
    - Comprehensive audit logging of all validation attempts
"""

import hashlib
import sys
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from models.database import AttackPath, PrivescPath, get_db

# Add report-processor to path for the validator
sys.path.insert(0, "/app/report-processor")

router = APIRouter(prefix="/poc-validation", tags=["PoC Validation"])


# ============================================================================
# Pydantic Schemas for PoC Validation
# ============================================================================


class ValidationStatus:
    """Validation status constants."""

    PENDING = "pending"
    VALIDATING = "validating"
    VALIDATED_EXPLOITABLE = "validated_exploitable"
    VALIDATED_BLOCKED = "validated_blocked"
    VALIDATION_FAILED = "validation_failed"


class PoCValidationRequest(BaseModel):
    """Request to validate a path."""

    dry_run: bool = Field(
        default=False, description="Preview commands without executing"
    )


class PoCValidationEvidence(BaseModel):
    """Evidence from PoC validation."""

    command: str
    output: str | None = None
    success: bool
    timestamp: datetime | None = None
    error: str | None = None
    original_command: str | None = Field(
        default=None, description="Original command if transformed"
    )
    transformed: bool = Field(
        default=False, description="Whether command was transformed for safety"
    )
    dry_run: bool = Field(default=False, description="Whether this was a dry run")


class PoCValidationResponse(BaseModel):
    """Response from PoC validation."""

    path_id: int
    path_type: str = Field(description="'attack' or 'privesc'")
    validation_status: str = Field(
        description="pending, validating, validated_exploitable, validated_blocked, or validation_failed"
    )
    validation_timestamp: datetime | None = None
    evidence: list[PoCValidationEvidence] = []
    error: str | None = None


class PoCBatchValidationRequest(BaseModel):
    """Request for batch validation."""

    path_ids: list[int] = Field(min_length=1, max_length=50)
    path_type: str = Field(default="attack", pattern="^(attack|privesc)$")
    dry_run: bool = False


class PoCBatchValidationResponse(BaseModel):
    """Response from batch validation."""

    total: int
    validated: int
    failed: int
    results: list[PoCValidationResponse]


class PoCValidationHistoryEntry(BaseModel):
    """Single entry in validation history."""

    path_id: int
    path_type: str
    validation_status: str
    validation_timestamp: datetime
    path_name: str | None = None


class PoCValidationHistoryResponse(BaseModel):
    """Response for validation history."""

    entries: list[PoCValidationHistoryEntry]
    total: int


class CommandSafetyCheckRequest(BaseModel):
    """Request to check if a command is safe."""

    command: str = Field(min_length=1, max_length=2000)


class CommandSafetyCheckResponse(BaseModel):
    """Response for command safety check."""

    command: str
    is_safe: bool
    reason: str
    suggested_alternative: str | None = None


# ============================================================================
# Helper Functions
# ============================================================================


def _get_poc_validator():
    """Get or create PoCValidator instance."""
    try:
        from poc_validator import PoCValidator

        return PoCValidator(timeout=30)
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"PoC validator not available: {str(e)}",
        )


def _convert_attack_path_to_dict(path: AttackPath) -> dict:
    """Convert AttackPath model to dictionary for validation."""
    return {
        "id": path.id,
        "path_id": path.path_id,
        "name": path.name,
        "description": path.description,
        "poc_steps": path.poc_steps or [],
        "poc_available": path.poc_available,
        "nodes": path.nodes or [],
        "edges": path.edges or [],
    }


def _convert_privesc_path_to_dict(path: PrivescPath) -> dict:
    """Convert PrivescPath model to dictionary for validation."""
    return {
        "id": path.id,
        "path_id": path.path_id,
        "escalation_method": path.escalation_method,
        "poc_commands": path.poc_commands or [],
        "path_nodes": path.path_nodes or [],
        "path_edges": path.path_edges or [],
    }


def _convert_evidence_to_schema(evidence_list: list[dict]) -> list[PoCValidationEvidence]:
    """Convert evidence dictionaries to Pydantic models."""
    result = []
    for ev in evidence_list:
        timestamp = ev.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except (ValueError, TypeError):
                timestamp = None
        elif not isinstance(timestamp, datetime):
            timestamp = None

        result.append(
            PoCValidationEvidence(
                command=ev.get("command", ""),
                output=ev.get("output"),
                success=ev.get("success", False),
                timestamp=timestamp,
                error=ev.get("error"),
                original_command=ev.get("original_command"),
                transformed=ev.get("transformed", False),
                dry_run=ev.get("dry_run", False),
            )
        )
    return result


def _generate_validation_id(path_id: int, path_type: str) -> str:
    """Generate a unique validation ID for tracking."""
    data = f"{path_id}:{path_type}:{datetime.utcnow().isoformat()}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


# ============================================================================
# API Endpoints
# ============================================================================


@router.post("/attack-paths/{path_id}/validate", response_model=PoCValidationResponse)
async def validate_attack_path(
    path_id: int,
    request: PoCValidationRequest = PoCValidationRequest(),
    db: Session = Depends(get_db),
):
    """
    Validate an attack path using safe read-only commands.

    This endpoint takes an attack path and validates its PoC steps by
    executing safe, transformed versions of the commands. Dangerous
    commands are transformed to read-only equivalents.

    Args:
        path_id: Database ID of the attack path
        request: Validation options (dry_run, etc.)

    Returns:
        PoCValidationResponse with validation status and evidence

    Raises:
        HTTPException 404: If attack path is not found
        HTTPException 500: If validation engine is not available
    """
    # Get the attack path
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    if not path.poc_available or not path.poc_steps:
        return PoCValidationResponse(
            path_id=path_id,
            path_type="attack",
            validation_status=ValidationStatus.VALIDATION_FAILED,
            validation_timestamp=datetime.utcnow(),
            evidence=[],
            error="No PoC steps available for this attack path",
        )

    # Get the validator
    validator = _get_poc_validator()

    # Convert path to dict for validation
    path_dict = _convert_attack_path_to_dict(path)

    # Validate
    result = validator.validate_attack_path(path_dict, dry_run=request.dry_run)

    # Parse timestamp
    timestamp = result.get("validation_timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except (ValueError, TypeError):
            timestamp = datetime.utcnow()

    return PoCValidationResponse(
        path_id=path_id,
        path_type="attack",
        validation_status=result.get("validation_status", ValidationStatus.VALIDATION_FAILED),
        validation_timestamp=timestamp,
        evidence=_convert_evidence_to_schema(result.get("evidence", [])),
        error=result.get("error"),
    )


@router.post("/privesc-paths/{path_id}/validate", response_model=PoCValidationResponse)
async def validate_privesc_path(
    path_id: int,
    request: PoCValidationRequest = PoCValidationRequest(),
    db: Session = Depends(get_db),
):
    """
    Validate a privilege escalation path using safe read-only commands.

    This endpoint takes a privilege escalation path and validates its
    PoC commands by executing safe, transformed versions.

    Args:
        path_id: Database ID of the privilege escalation path
        request: Validation options (dry_run, etc.)

    Returns:
        PoCValidationResponse with validation status and evidence

    Raises:
        HTTPException 404: If privesc path is not found
        HTTPException 500: If validation engine is not available
    """
    # Get the privesc path
    path = db.query(PrivescPath).filter(PrivescPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Privilege escalation path not found")

    if not path.poc_commands:
        return PoCValidationResponse(
            path_id=path_id,
            path_type="privesc",
            validation_status=ValidationStatus.VALIDATION_FAILED,
            validation_timestamp=datetime.utcnow(),
            evidence=[],
            error="No PoC commands available for this privilege escalation path",
        )

    # Get the validator
    validator = _get_poc_validator()

    # Convert path to dict for validation
    path_dict = _convert_privesc_path_to_dict(path)

    # Validate
    result = validator.validate_privesc_path(path_dict, dry_run=request.dry_run)

    # Parse timestamp
    timestamp = result.get("validation_timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except (ValueError, TypeError):
            timestamp = datetime.utcnow()

    return PoCValidationResponse(
        path_id=path_id,
        path_type="privesc",
        validation_status=result.get("validation_status", ValidationStatus.VALIDATION_FAILED),
        validation_timestamp=timestamp,
        evidence=_convert_evidence_to_schema(result.get("evidence", [])),
        error=result.get("error"),
    )


@router.post("/batch-validate", response_model=PoCBatchValidationResponse)
async def batch_validate(
    request: PoCBatchValidationRequest,
    db: Session = Depends(get_db),
):
    """
    Batch validate multiple paths.

    Validates multiple attack paths or privilege escalation paths in a
    single request. Limited to 50 paths per request to prevent abuse.

    Args:
        request: Batch validation request with path IDs and type

    Returns:
        PoCBatchValidationResponse with all validation results

    Raises:
        HTTPException 400: If no valid paths found
        HTTPException 500: If validation engine is not available
    """
    # Get the validator
    validator = _get_poc_validator()

    results: list[PoCValidationResponse] = []
    validated_count = 0
    failed_count = 0

    for path_id in request.path_ids:
        try:
            if request.path_type == "attack":
                path = db.query(AttackPath).filter(AttackPath.id == path_id).first()
                if not path:
                    results.append(
                        PoCValidationResponse(
                            path_id=path_id,
                            path_type="attack",
                            validation_status=ValidationStatus.VALIDATION_FAILED,
                            validation_timestamp=datetime.utcnow(),
                            evidence=[],
                            error="Attack path not found",
                        )
                    )
                    failed_count += 1
                    continue

                path_dict = _convert_attack_path_to_dict(path)
                result = validator.validate_attack_path(path_dict, dry_run=request.dry_run)
            else:
                path = db.query(PrivescPath).filter(PrivescPath.id == path_id).first()
                if not path:
                    results.append(
                        PoCValidationResponse(
                            path_id=path_id,
                            path_type="privesc",
                            validation_status=ValidationStatus.VALIDATION_FAILED,
                            validation_timestamp=datetime.utcnow(),
                            evidence=[],
                            error="Privilege escalation path not found",
                        )
                    )
                    failed_count += 1
                    continue

                path_dict = _convert_privesc_path_to_dict(path)
                result = validator.validate_privesc_path(path_dict, dry_run=request.dry_run)

            # Parse timestamp
            timestamp = result.get("validation_timestamp")
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except (ValueError, TypeError):
                    timestamp = datetime.utcnow()

            response = PoCValidationResponse(
                path_id=path_id,
                path_type=request.path_type,
                validation_status=result.get("validation_status", ValidationStatus.VALIDATION_FAILED),
                validation_timestamp=timestamp,
                evidence=_convert_evidence_to_schema(result.get("evidence", [])),
                error=result.get("error"),
            )
            results.append(response)

            if result.get("validation_status") in [
                ValidationStatus.VALIDATED_EXPLOITABLE,
                ValidationStatus.VALIDATED_BLOCKED,
            ]:
                validated_count += 1
            else:
                failed_count += 1

        except Exception as e:
            results.append(
                PoCValidationResponse(
                    path_id=path_id,
                    path_type=request.path_type,
                    validation_status=ValidationStatus.VALIDATION_FAILED,
                    validation_timestamp=datetime.utcnow(),
                    evidence=[],
                    error=str(e),
                )
            )
            failed_count += 1

    return PoCBatchValidationResponse(
        total=len(request.path_ids),
        validated=validated_count,
        failed=failed_count,
        results=results,
    )


@router.get("/status/{validation_id}", response_model=PoCValidationResponse)
async def get_validation_status(
    validation_id: str,
    db: Session = Depends(get_db),
):
    """
    Get status of a validation.

    Note: Currently validations are synchronous, so this endpoint is
    primarily for future async validation support. Returns 404 for
    unknown validation IDs.

    Args:
        validation_id: The validation tracking ID

    Returns:
        PoCValidationResponse with current status

    Raises:
        HTTPException 404: If validation not found
    """
    # For now, validations are synchronous, so we don't have stored state
    # This endpoint is a placeholder for future async validation support
    raise HTTPException(
        status_code=404,
        detail="Validation not found. Note: Validations are currently synchronous.",
    )


@router.get("/history", response_model=PoCValidationHistoryResponse)
async def get_validation_history(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum entries to return"),
    offset: int = Query(default=0, ge=0, description="Number of entries to skip"),
    path_type: str | None = Query(
        default=None, pattern="^(attack|privesc)$", description="Filter by path type"
    ),
    db: Session = Depends(get_db),
):
    """
    Get validation history.

    Returns recent paths that have been validated, ordered by most recent
    first. This pulls from the paths themselves as validation state is
    currently not persisted separately.

    Note: This returns paths that have PoC data available. Future versions
    may persist validation results separately.

    Args:
        limit: Maximum number of entries (1-200)
        offset: Number of entries to skip for pagination
        path_type: Optional filter for 'attack' or 'privesc'

    Returns:
        PoCValidationHistoryResponse with validation history
    """
    entries: list[PoCValidationHistoryEntry] = []

    # Get attack paths with PoC data
    if path_type is None or path_type == "attack":
        attack_paths = (
            db.query(AttackPath)
            .filter(AttackPath.poc_available == True)  # noqa: E712
            .order_by(desc(AttackPath.updated_at))
            .offset(offset if path_type == "attack" else 0)
            .limit(limit if path_type == "attack" else limit // 2)
            .all()
        )

        for path in attack_paths:
            entries.append(
                PoCValidationHistoryEntry(
                    path_id=path.id,
                    path_type="attack",
                    validation_status="pending",  # Status not persisted yet
                    validation_timestamp=path.updated_at or path.created_at,
                    path_name=path.name,
                )
            )

    # Get privesc paths with PoC data
    if path_type is None or path_type == "privesc":
        privesc_paths = (
            db.query(PrivescPath)
            .filter(PrivescPath.poc_commands != None)  # noqa: E711
            .order_by(desc(PrivescPath.updated_at))
            .offset(offset if path_type == "privesc" else 0)
            .limit(limit if path_type == "privesc" else limit // 2)
            .all()
        )

        for path in privesc_paths:
            entries.append(
                PoCValidationHistoryEntry(
                    path_id=path.id,
                    path_type="privesc",
                    validation_status="pending",  # Status not persisted yet
                    validation_timestamp=path.updated_at or path.created_at,
                    path_name=path.escalation_method,
                )
            )

    # Sort combined entries by timestamp
    entries.sort(key=lambda e: e.validation_timestamp or datetime.min, reverse=True)

    # Apply final pagination
    entries = entries[offset : offset + limit]

    # Get total count
    total_attack = db.query(AttackPath).filter(AttackPath.poc_available == True).count()  # noqa: E712
    total_privesc = db.query(PrivescPath).filter(PrivescPath.poc_commands != None).count()  # noqa: E711

    if path_type == "attack":
        total = total_attack
    elif path_type == "privesc":
        total = total_privesc
    else:
        total = total_attack + total_privesc

    return PoCValidationHistoryResponse(
        entries=entries,
        total=total,
    )


@router.post("/check-command", response_model=CommandSafetyCheckResponse)
async def check_command_safety(
    request: CommandSafetyCheckRequest,
):
    """
    Check if a command is safe to execute.

    This endpoint allows checking whether a given command would be
    allowed by the validation engine. Useful for testing and debugging.

    Args:
        request: Command to check

    Returns:
        CommandSafetyCheckResponse with safety assessment
    """
    validator = _get_poc_validator()

    is_safe, reason = validator.is_safe_command(request.command)

    # Try to find a safe alternative if command is blocked
    suggested_alternative = None
    if not is_safe:
        step = {"command": request.command}
        safe_cmd = validator.transform_to_safe_command(step)
        if safe_cmd and safe_cmd != request.command:
            suggested_alternative = safe_cmd

    return CommandSafetyCheckResponse(
        command=request.command,
        is_safe=is_safe,
        reason=reason,
        suggested_alternative=suggested_alternative,
    )


@router.get("/allowed-commands")
async def get_allowed_commands():
    """
    Get the list of allowed command patterns.

    Returns the allowlist used by the validation engine for reference.
    Useful for understanding what commands can be validated.

    Returns:
        Dictionary of CLI tools and their allowed patterns
    """
    try:
        from poc_validator import ALLOWED_COMMANDS, BLOCKED_COMMANDS

        return {
            "allowed_patterns": ALLOWED_COMMANDS,
            "blocked_keywords": BLOCKED_COMMANDS,
            "note": "Commands must match an allowed pattern and not contain any blocked keywords",
        }
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PoC validator not available",
        )


# ============================================================================
# Pydantic Schemas for Future Integration (to be added to schemas.py)
# ============================================================================
#
# The following schemas should be added to api/models/schemas.py when
# integrating this feature:
#
# from enum import Enum
#
# class ValidationStatus(str, Enum):
#     """Validation status enumeration."""
#     pending = "pending"
#     validating = "validating"
#     validated_exploitable = "validated_exploitable"
#     validated_blocked = "validated_blocked"
#     validation_failed = "validation_failed"
#
#
# class PoCValidationRequest(BaseModel):
#     """Request to validate a path."""
#     dry_run: bool = Field(default=False, description="Preview commands without executing")
#
#
# class PoCValidationEvidence(BaseModel):
#     """Evidence from PoC validation."""
#     command: str
#     output: str | None = None
#     success: bool
#     timestamp: datetime | None = None
#     error: str | None = None
#     original_command: str | None = Field(default=None, description="Original command if transformed")
#     transformed: bool = Field(default=False, description="Whether command was transformed for safety")
#     dry_run: bool = Field(default=False, description="Whether this was a dry run")
#
#
# class PoCValidationResponse(BaseModel):
#     """Response from PoC validation."""
#     path_id: int
#     path_type: str = Field(description="'attack' or 'privesc'")
#     validation_status: str = Field(
#         description="pending, validating, validated_exploitable, validated_blocked, or validation_failed"
#     )
#     validation_timestamp: datetime | None = None
#     evidence: list[PoCValidationEvidence] = []
#     error: str | None = None
#
#
# class PoCBatchValidationRequest(BaseModel):
#     """Request for batch validation."""
#     path_ids: list[int] = Field(min_length=1, max_length=50)
#     path_type: str = Field(default="attack", pattern="^(attack|privesc)$")
#     dry_run: bool = False
#
#
# class PoCBatchValidationResponse(BaseModel):
#     """Response from batch validation."""
#     total: int
#     validated: int
#     failed: int
#     results: list[PoCValidationResponse]
#
#
# class PoCValidationHistoryEntry(BaseModel):
#     """Single entry in validation history."""
#     path_id: int
#     path_type: str
#     validation_status: str
#     validation_timestamp: datetime
#     path_name: str | None = None
#
#
# class PoCValidationHistoryResponse(BaseModel):
#     """Response for validation history."""
#     entries: list[PoCValidationHistoryEntry]
#     total: int
#
#
# class CommandSafetyCheckRequest(BaseModel):
#     """Request to check if a command is safe."""
#     command: str = Field(min_length=1, max_length=2000)
#
#
# class CommandSafetyCheckResponse(BaseModel):
#     """Response for command safety check."""
#     command: str
#     is_safe: bool
#     reason: str
#     suggested_alternative: str | None = None
#
