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

from models.database import AttackPath, Finding, FindingValidation, PrivescPath, get_db
from models.schemas import (
    FindingValidationCreate,
    FindingValidationEvidence,
    FindingValidationResponse,
)

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


@router.post("/findings/{finding_id}/validate", response_model=FindingValidationResponse)
async def validate_finding(
    finding_id: int,
    request: FindingValidationCreate = FindingValidationCreate(),
    db: Session = Depends(get_db),
):
    """
    Validate a finding using safe read-only commands.

    This endpoint validates individual findings by generating and executing
    safe verification commands based on the finding type. The validation
    results are persisted for future reference.

    Args:
        finding_id: Database ID of the finding
        request: Validation options (dry_run, etc.)

    Returns:
        FindingValidationResponse with validation status and evidence

    Raises:
        HTTPException 404: If finding is not found
        HTTPException 500: If validation engine is not available
    """
    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get the validator
    validator = _get_poc_validator()

    # Generate validation ID
    validation_id = _generate_validation_id(finding_id, "finding")

    # Build validation commands based on finding type
    poc_commands = _generate_finding_poc_commands(finding)

    if not poc_commands:
        # No PoC commands available for this finding type
        validation = FindingValidation(
            validation_id=validation_id,
            finding_id=finding_id,
            validation_status="no_poc_available",
            validation_timestamp=datetime.utcnow(),
            evidence=[],
            error_message="No PoC commands available for this finding type",
            dry_run=request.dry_run,
        )
        db.add(validation)
        db.commit()
        db.refresh(validation)

        return FindingValidationResponse(
            id=validation.id,
            validation_id=validation.validation_id,
            finding_id=finding_id,
            validation_status=validation.validation_status,
            validation_timestamp=validation.validation_timestamp,
            evidence=[],
            error_message=validation.error_message,
            dry_run=validation.dry_run,
            created_at=validation.created_at,
        )

    # Execute validation
    evidence = []
    all_success = True

    for cmd in poc_commands:
        is_safe, reason = validator.is_safe_command(cmd)

        if request.dry_run:
            evidence.append({
                "command": cmd,
                "output": f"[DRY RUN] Command would be executed: {cmd}",
                "success": is_safe,
                "timestamp": datetime.utcnow().isoformat(),
                "error": None if is_safe else reason,
            })
        elif is_safe:
            # Execute the command
            result = validator.execute_safe_command(cmd)
            evidence.append({
                "command": cmd,
                "output": result.get("output", ""),
                "success": result.get("success", False),
                "timestamp": datetime.utcnow().isoformat(),
                "error": result.get("error"),
            })
            if not result.get("success", False):
                all_success = False
        else:
            # Command is not safe, try to transform it
            safe_cmd = validator.transform_to_safe_command({"command": cmd})
            if safe_cmd:
                result = validator.execute_safe_command(safe_cmd)
                evidence.append({
                    "command": safe_cmd,
                    "output": result.get("output", ""),
                    "success": result.get("success", False),
                    "timestamp": datetime.utcnow().isoformat(),
                    "error": result.get("error"),
                })
                if not result.get("success", False):
                    all_success = False
            else:
                evidence.append({
                    "command": cmd,
                    "output": None,
                    "success": False,
                    "timestamp": datetime.utcnow().isoformat(),
                    "error": f"Command blocked: {reason}",
                })
                all_success = False

    # Determine validation status
    if request.dry_run:
        status = "dry_run_complete"
    elif all_success:
        status = "validated"
    else:
        status = "validation_failed"

    # Persist validation result
    validation = FindingValidation(
        validation_id=validation_id,
        finding_id=finding_id,
        validation_status=status,
        validation_timestamp=datetime.utcnow(),
        evidence=evidence,
        dry_run=request.dry_run,
    )
    db.add(validation)
    db.commit()
    db.refresh(validation)

    # Convert evidence to response schema
    evidence_response = [
        FindingValidationEvidence(
            command=e.get("command", ""),
            output=e.get("output"),
            success=e.get("success", False),
            timestamp=datetime.fromisoformat(e["timestamp"]) if e.get("timestamp") else None,
            error=e.get("error"),
        )
        for e in evidence
    ]

    return FindingValidationResponse(
        id=validation.id,
        validation_id=validation.validation_id,
        finding_id=finding_id,
        validation_status=validation.validation_status,
        validation_timestamp=validation.validation_timestamp,
        evidence=evidence_response,
        error_message=validation.error_message,
        dry_run=validation.dry_run,
        created_at=validation.created_at,
    )


def _generate_finding_poc_commands(finding: Finding) -> list[str]:
    """
    Generate PoC commands for a finding based on its type.

    This function analyzes the finding and generates appropriate
    read-only verification commands.
    """
    commands = []

    # Common patterns based on finding category
    tool = finding.tool.lower() if finding.tool else ""
    finding_id_str = finding.finding_id.lower() if finding.finding_id else ""
    resource_type = finding.resource_type.lower() if finding.resource_type else ""
    resource_id = finding.resource_id or ""

    # AWS-specific checks
    if "aws" in tool or "prowler" in tool or "scoutsuite" in tool:
        # S3 bucket checks
        if "s3" in finding_id_str or "s3" in resource_type:
            if resource_id.startswith("arn:aws:s3"):
                bucket_name = resource_id.split(":")[-1].split("/")[0]
            else:
                bucket_name = resource_id
            commands.append(f"aws s3api get-bucket-acl --bucket {bucket_name}")
            commands.append(f"aws s3api get-bucket-policy --bucket {bucket_name}")
            commands.append(f"aws s3api get-public-access-block --bucket {bucket_name}")

        # IAM checks
        elif "iam" in finding_id_str or "iam" in resource_type:
            if "user" in finding_id_str or "user" in resource_type:
                if "/" in resource_id:
                    user_name = resource_id.split("/")[-1]
                else:
                    user_name = resource_id
                commands.append(f"aws iam get-user --user-name {user_name}")
                commands.append(f"aws iam list-user-policies --user-name {user_name}")
            elif "role" in finding_id_str or "role" in resource_type:
                if "/" in resource_id:
                    role_name = resource_id.split("/")[-1]
                else:
                    role_name = resource_id
                commands.append(f"aws iam get-role --role-name {role_name}")
                commands.append(f"aws iam list-role-policies --role-name {role_name}")
            elif "policy" in finding_id_str:
                commands.append(f"aws iam get-policy --policy-arn {resource_id}")

        # EC2 checks
        elif "ec2" in finding_id_str or "ec2" in resource_type:
            if "security" in finding_id_str or "sg-" in resource_id:
                if resource_id.startswith("sg-"):
                    commands.append(f"aws ec2 describe-security-groups --group-ids {resource_id}")
                else:
                    commands.append("aws ec2 describe-security-groups")
            elif "instance" in resource_type or "i-" in resource_id:
                if resource_id.startswith("i-"):
                    commands.append(f"aws ec2 describe-instances --instance-ids {resource_id}")

        # RDS checks
        elif "rds" in finding_id_str or "rds" in resource_type:
            if ":" in resource_id:
                db_id = resource_id.split(":")[-1]
            else:
                db_id = resource_id
            commands.append(f"aws rds describe-db-instances --db-instance-identifier {db_id}")

        # Lambda checks
        elif "lambda" in finding_id_str or "lambda" in resource_type:
            if ":" in resource_id:
                func_name = resource_id.split(":")[-1]
            else:
                func_name = resource_id
            commands.append(f"aws lambda get-function --function-name {func_name}")
            commands.append(f"aws lambda get-function-configuration --function-name {func_name}")

        # CloudTrail checks
        elif "cloudtrail" in finding_id_str or "cloudtrail" in resource_type:
            commands.append("aws cloudtrail describe-trails")

        # KMS checks
        elif "kms" in finding_id_str or "kms" in resource_type:
            if resource_id:
                commands.append(f"aws kms describe-key --key-id {resource_id}")

    # Fallback: if no specific commands generated, try generic describe
    if not commands and resource_id:
        # Generic AWS describe patterns
        if resource_id.startswith("arn:aws:"):
            parts = resource_id.split(":")
            if len(parts) >= 6:
                service = parts[2]
                commands.append(f"aws {service} describe-* --help")  # Safe help command

    return commands


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
