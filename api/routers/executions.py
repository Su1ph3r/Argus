"""Tool Execution Management API endpoints."""

import logging
import re
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from models.database import EnumerateIamResult, PacuResult, ToolExecution, get_db
from models.schemas import (
    ToolExecutionListResponse,
    ToolExecutionLogsResponse,
    ToolExecutionResponse,
    ToolExecutionStartResponse,
)
from services.docker_executor import (
    DockerExecutor,
    ExecutionStatus,
    ToolType,
    get_docker_executor,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/executions", tags=["Tool Executions"])


def _get_module_category(module_name: str) -> str:
    """Get the category for a Pacu module based on naming convention."""
    if module_name.startswith(
        (
            "iam__enum",
            "ec2__enum",
            "lambda__enum",
            "rds__enum",
            "ecs__enum",
            "eks__enum",
            "sns__enum",
            "secrets__enum",
            "dynamodb__enum",
            "ebs__enum",
            "aws__enum",
            "acm__enum",
            "apigateway__enum",
            "cognito__enum",
            "ecr__enum",
        )
    ):
        return "ENUM"
    elif "privesc" in module_name or "escalat" in module_name:
        return "ESCALATE"
    elif "backdoor" in module_name or "persist" in module_name:
        return "PERSIST"
    elif "download" in module_name or "exfil" in module_name or "explore_snapshot" in module_name:
        return "EXFIL"
    elif "detection" in module_name or "cloudtrail" in module_name or "guardduty" in module_name:
        return "EVADE"
    else:
        return "EXPLOIT"


def _parse_pacu_output(logs: str) -> dict:
    """Parse Pacu output to extract useful information."""
    result = {
        "account_id": None,
        "resources_affected": 0,
        "permissions_count": 0,
    }

    # Extract account ID from logs
    account_match = re.search(r"account:\s*(\d{12})", logs, re.IGNORECASE)
    if account_match:
        result["account_id"] = account_match.group(1)

    # Extract permission count
    perm_match = re.search(r"(\d+)\s+Confirmed permissions", logs, re.IGNORECASE)
    if perm_match:
        result["permissions_count"] = int(perm_match.group(1))
        result["resources_affected"] = 1

    return result


def _create_pacu_result(db: Session, execution: ToolExecution, logs: str = "") -> None:
    """Create a PacuResult record from a completed Pacu execution."""
    try:
        config = execution.config or {}
        module_name = config.get("module", "unknown")
        session_name = config.get("session_name", "api-session")

        # Parse output for additional details
        parsed = _parse_pacu_output(logs)

        # Calculate execution time
        execution_time_ms = None
        if execution.started_at and execution.completed_at:
            delta = execution.completed_at - execution.started_at
            execution_time_ms = int(delta.total_seconds() * 1000)

        # Create result record
        pacu_result = PacuResult(
            result_id=execution.execution_id,
            session_name=session_name,
            module_name=module_name,
            module_category=_get_module_category(module_name),
            execution_status="success" if execution.status == "completed" else "failed",
            target_account_id=parsed.get("account_id"),
            resources_affected=parsed.get("resources_affected", 0),
            error_message=execution.error_message if execution.status == "failed" else None,
            execution_time_ms=execution_time_ms,
        )

        db.add(pacu_result)
        db.commit()
        logger.info(f"Created PacuResult for execution {execution.execution_id}")
    except Exception as e:
        logger.error(f"Failed to create PacuResult: {e}")
        db.rollback()


# High-risk permission patterns for enumerate-iam
HIGH_RISK_PERMISSIONS = {
    # Admin-level permissions
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:CreatePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    # Data access permissions
    "s3:GetObject",
    "s3:ListBucket",
    "s3:PutObject",
    "s3:DeleteObject",
    "dynamodb:GetItem",
    "dynamodb:Scan",
    "dynamodb:Query",
    "dynamodb:PutItem",
    "rds:DownloadDBLogFilePortion",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "kms:Decrypt",
    # Privilege escalation permissions
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "cloudformation:CreateStack",
    "glue:CreateDevEndpoint",
}

ADMIN_PERMISSIONS = {
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:CreatePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:DeleteUser",
    "iam:DeleteRole",
}

PRIVESC_PERMISSIONS = {
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    "sts:AssumeRole",
    "cloudformation:CreateStack",
    "glue:CreateDevEndpoint",
    "ec2:RunInstances",
    "datapipeline:CreatePipeline",
}

DATA_ACCESS_PERMISSIONS = {
    "s3:GetObject",
    "s3:ListBucket",
    "dynamodb:GetItem",
    "dynamodb:Scan",
    "dynamodb:Query",
    "rds:DownloadDBLogFilePortion",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "kms:Decrypt",
    "sqs:ReceiveMessage",
    "sns:Subscribe",
}


def _parse_enumerate_iam_output(logs: str) -> dict:
    """Parse enumerate-iam output to extract permission information."""
    confirmed_permissions = []
    denied_permissions = []
    error_permissions = []
    high_risk_permissions = []

    for line in logs.split("\n"):
        # Parse successful permission checks: "-- service.api_call() worked!"
        worked_match = re.search(r"--\s+(\w+)\.(\w+)\(\)\s+worked!", line)
        if worked_match:
            service = worked_match.group(1)
            action = worked_match.group(2)
            permission = f"{service}:{action}"
            confirmed_permissions.append(permission)

            # Check if it's a high-risk permission (case-insensitive check)
            for hr_perm in HIGH_RISK_PERMISSIONS:
                if hr_perm.lower() == permission.lower():
                    high_risk_permissions.append(permission)
                    break
            continue

        # Parse denied permissions: typically "AccessDenied" in the message
        denied_match = re.search(
            r"--\s+(\w+)\.(\w+)\(\).*(?:AccessDenied|Denied|Unauthorized)", line, re.IGNORECASE
        )
        if denied_match:
            service = denied_match.group(1)
            action = denied_match.group(2)
            denied_permissions.append(f"{service}:{action}")
            continue

        # Parse error permissions: other errors
        error_match = re.search(
            r"--\s+(\w+)\.(\w+)\(\).*(?:error|exception|failed)", line, re.IGNORECASE
        )
        if error_match:
            service = error_match.group(1)
            action = error_match.group(2)
            error_permissions.append(f"{service}:{action}")

    # Determine capabilities based on confirmed permissions
    confirmed_lower = {p.lower() for p in confirmed_permissions}
    admin_capable = any(p.lower() in confirmed_lower for p in ADMIN_PERMISSIONS)
    privesc_capable = any(p.lower() in confirmed_lower for p in PRIVESC_PERMISSIONS)
    data_access_capable = any(p.lower() in confirmed_lower for p in DATA_ACCESS_PERMISSIONS)

    return {
        "confirmed_permissions": confirmed_permissions,
        "denied_permissions": denied_permissions,
        "error_permissions": error_permissions,
        "high_risk_permissions": high_risk_permissions,
        "permission_count": len(confirmed_permissions),
        "admin_capable": admin_capable,
        "privesc_capable": privesc_capable,
        "data_access_capable": data_access_capable,
    }


def _create_enumerate_iam_result(db: Session, execution: ToolExecution, logs: str = "") -> None:
    """Create an EnumerateIamResult record from a completed enumerate-iam execution."""
    try:
        config = execution.config or {}

        # Parse output for permission details
        parsed = _parse_enumerate_iam_output(logs)

        # Check if a result already exists for this execution
        existing = (
            db.query(EnumerateIamResult)
            .filter(EnumerateIamResult.result_id == execution.execution_id)
            .first()
        )

        if existing:
            logger.info(f"EnumerateIamResult already exists for execution {execution.execution_id}")
            return

        # Create result record
        iam_result = EnumerateIamResult(
            result_id=execution.execution_id,
            principal_arn=config.get("profile", "unknown"),
            principal_name=config.get("profile", "api-execution"),
            principal_type="User",  # Default, could be determined from credentials
            confirmed_permissions=parsed["confirmed_permissions"],
            denied_permissions=parsed["denied_permissions"],
            error_permissions=parsed["error_permissions"],
            high_risk_permissions=parsed["high_risk_permissions"],
            permission_count=parsed["permission_count"],
            admin_capable=parsed["admin_capable"],
            privesc_capable=parsed["privesc_capable"],
            data_access_capable=parsed["data_access_capable"],
        )

        db.add(iam_result)
        db.commit()
        logger.info(
            f"Created EnumerateIamResult for execution {execution.execution_id} with {parsed['permission_count']} permissions"
        )
    except Exception as e:
        logger.error(f"Failed to create EnumerateIamResult: {e}")
        db.rollback()


async def _update_execution_status(
    db: Session,
    execution_id: str,
    executor: DockerExecutor,
):
    """Background task to update execution status from Docker."""
    try:
        execution = (
            db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()
        )

        if not execution or not execution.container_id:
            return

        status_info = await executor.get_execution_status(execution.container_id)

        if status_info.get("execution_status") == ExecutionStatus.COMPLETED:
            execution.status = "completed"
            execution.completed_at = datetime.utcnow()
            execution.exit_code = status_info.get("exit_code", 0)
        elif status_info.get("execution_status") == ExecutionStatus.FAILED:
            execution.status = "failed"
            execution.completed_at = datetime.utcnow()
            execution.exit_code = status_info.get("exit_code")
            execution.error_message = status_info.get("logs", "")[:2000]

        db.commit()
    except Exception as e:
        logger.error(f"Failed to update execution status: {e}")


@router.get("", response_model=ToolExecutionListResponse)
@router.get("/", response_model=ToolExecutionListResponse)
async def list_executions(
    db: Session = Depends(get_db),
    tool_name: str | None = Query(None, description="Filter by tool name"),
    status: str | None = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List tool executions with optional filters."""
    query = db.query(ToolExecution)

    if tool_name:
        query = query.filter(ToolExecution.tool_name == tool_name)

    if status:
        query = query.filter(ToolExecution.status == status.lower())

    total = query.count()

    executions = (
        query.order_by(desc(ToolExecution.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return ToolExecutionListResponse(
        executions=[ToolExecutionResponse.model_validate(e) for e in executions],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{execution_id}", response_model=ToolExecutionResponse)
async def get_execution(
    execution_id: str,
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = None,
):
    """Get execution details and update status from Docker if running."""
    execution = db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    # If execution is running, check Docker for updated status
    if execution.status == "running" and execution.container_id:
        try:
            executor = get_docker_executor()
            status_info = await executor.get_execution_status(execution.container_id)
            logs = status_info.get("logs", "")

            if status_info.get("execution_status") == ExecutionStatus.COMPLETED:
                execution.status = "completed"
                execution.completed_at = datetime.utcnow()
                execution.exit_code = status_info.get("exit_code", 0)
                db.commit()

                # Create tool-specific result records
                if execution.tool_name == "pacu":
                    _create_pacu_result(db, execution, logs)
                elif execution.tool_name == "enumerate-iam":
                    _create_enumerate_iam_result(db, execution, logs)

            elif status_info.get("execution_status") == ExecutionStatus.FAILED:
                execution.status = "failed"
                execution.completed_at = datetime.utcnow()
                execution.exit_code = status_info.get("exit_code")
                execution.error_message = logs[:2000] if logs else ""
                db.commit()

                # Create tool-specific result records (even for failures)
                if execution.tool_name == "pacu":
                    _create_pacu_result(db, execution, logs)
                elif execution.tool_name == "enumerate-iam":
                    _create_enumerate_iam_result(db, execution, logs)

        except Exception as e:
            logger.warning(f"Could not check Docker status: {e}")

    return ToolExecutionResponse.model_validate(execution)


@router.get("/{execution_id}/logs", response_model=ToolExecutionLogsResponse)
async def get_execution_logs(
    execution_id: str,
    tail: int = Query(100, ge=1, le=1000, description="Number of log lines"),
    db: Session = Depends(get_db),
):
    """Get logs from a tool execution."""
    execution = db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    if not execution.container_id:
        return ToolExecutionLogsResponse(
            execution_id=execution_id,
            logs="No container associated with this execution",
            status=execution.status,
        )

    try:
        executor = get_docker_executor()
        logs = await executor.get_execution_logs(execution.container_id, tail=tail)
        return ToolExecutionLogsResponse(
            execution_id=execution_id,
            logs=logs,
            status=execution.status,
        )
    except Exception as e:
        return ToolExecutionLogsResponse(
            execution_id=execution_id,
            logs=f"Error retrieving logs: {e}",
            status=execution.status,
        )


@router.post("/{execution_id}/stop")
async def stop_execution(
    execution_id: str,
    db: Session = Depends(get_db),
):
    """Stop a running execution."""
    execution = db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    if execution.status != "running":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot stop execution with status: {execution.status}",
        )

    if not execution.container_id:
        raise HTTPException(
            status_code=400,
            detail="No container associated with this execution",
        )

    try:
        executor = get_docker_executor()
        result = await executor.stop_execution(execution.container_id)

        execution.status = "cancelled"
        execution.completed_at = datetime.utcnow()
        db.commit()

        return {
            "message": "Execution stopped",
            "execution_id": execution_id,
            "status": "cancelled",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop execution: {e}")


@router.delete("/{execution_id}")
async def delete_execution(
    execution_id: str,
    cleanup_container: bool = Query(True, description="Also remove the Docker container"),
    db: Session = Depends(get_db),
):
    """Delete an execution record and optionally cleanup the container."""
    execution = db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    # Cleanup container if requested
    if cleanup_container and execution.container_id:
        try:
            executor = get_docker_executor()
            await executor.cleanup_container(execution.container_id)
        except Exception as e:
            logger.warning(f"Failed to cleanup container: {e}")

    db.delete(execution)
    db.commit()

    return {"message": "Execution deleted", "execution_id": execution_id}


@router.get("/docker/status")
async def get_docker_status():
    """Check if Docker is available for tool execution."""
    try:
        executor = get_docker_executor()
        available = executor.is_available()
        return {
            "docker_available": available,
            "message": "Docker is ready for tool execution"
            if available
            else "Docker is not available",
        }
    except Exception as e:
        return {
            "docker_available": False,
            "message": f"Docker error: {e}",
        }


async def start_tool_execution(
    tool_name: str,
    tool_type: ToolType,
    config: dict,
    command: list = None,
    environment: dict = None,
    entrypoint: str = None,
    db: Session = None,
) -> ToolExecutionStartResponse:
    """
    Helper function to start a tool execution.
    Used by individual tool routers (cloudfox, pacu, etc.)
    """
    execution_id = str(uuid.uuid4())[:12]

    # Create execution record
    execution = ToolExecution(
        execution_id=execution_id,
        tool_name=tool_name,
        tool_type=tool_type.value,
        status="pending",
        config=config,
        created_at=datetime.utcnow(),
    )
    db.add(execution)
    db.commit()

    try:
        executor = get_docker_executor()

        # Check if Docker is available
        if not executor.is_available():
            execution.status = "failed"
            execution.error_message = "Docker is not available"
            db.commit()
            return ToolExecutionStartResponse(
                execution_id=execution_id,
                tool_name=tool_name,
                status="failed",
                message="Docker is not available for tool execution",
                error="Docker connection failed",
            )

        # Start the execution
        result = await executor.start_execution(
            tool_type=tool_type,
            command=command,
            environment=environment,
            entrypoint=entrypoint,
        )

        if result.get("status") == ExecutionStatus.FAILED:
            execution.status = "failed"
            execution.error_message = result.get("error", "Unknown error")
            db.commit()
            return ToolExecutionStartResponse(
                execution_id=execution_id,
                tool_name=tool_name,
                status="failed",
                message="Failed to start execution",
                error=result.get("error"),
            )

        # Update execution with container info
        execution.status = "running"
        execution.container_id = result.get("container_id")
        execution.started_at = datetime.utcnow()
        db.commit()

        return ToolExecutionStartResponse(
            execution_id=execution_id,
            tool_name=tool_name,
            status="running",
            message=f"{tool_name} execution started successfully",
            container_id=result.get("container_id"),
        )

    except Exception as e:
        logger.error(f"Failed to start {tool_name} execution: {e}")
        execution.status = "failed"
        execution.error_message = str(e)
        db.commit()
        return ToolExecutionStartResponse(
            execution_id=execution_id,
            tool_name=tool_name,
            status="failed",
            message="Failed to start execution",
            error=str(e),
        )
