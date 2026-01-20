"""enumerate-iam Integration API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import EnumerateIamResult, get_db
from models.schemas import (
    EnumerateIamListResponse,
    EnumerateIamResultResponse,
    EnumerateIamRunRequest,
    EnumerateIamSummary,
    ToolExecutionStartResponse,
)
from routers.executions import start_tool_execution
from services.docker_executor import ToolType

router = APIRouter(prefix="/enumerate-iam", tags=["enumerate-iam"])


@router.get("", response_model=EnumerateIamListResponse)
@router.get("/", response_model=EnumerateIamListResponse)
async def list_enumerate_iam_results(
    db: Session = Depends(get_db),
    principal_type: str | None = Query(None, description="Filter by principal type"),
    privesc_capable: bool | None = Query(None, description="Filter by privesc capability"),
    admin_capable: bool | None = Query(None, description="Filter by admin capability"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List enumerate-iam results with optional filters."""
    query = db.query(EnumerateIamResult)

    if principal_type:
        query = query.filter(EnumerateIamResult.principal_type == principal_type)

    if privesc_capable is not None:
        query = query.filter(EnumerateIamResult.privesc_capable == privesc_capable)

    if admin_capable is not None:
        query = query.filter(EnumerateIamResult.admin_capable == admin_capable)

    total = query.count()

    results = (
        query.order_by(
            desc(EnumerateIamResult.permission_count), desc(EnumerateIamResult.created_at)
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return EnumerateIamListResponse(
        results=[EnumerateIamResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=EnumerateIamSummary)
async def get_enumerate_iam_summary(db: Session = Depends(get_db)):
    """Get summary statistics of enumerate-iam results."""
    total = db.query(EnumerateIamResult).count()
    privesc = (
        db.query(EnumerateIamResult).filter(EnumerateIamResult.privesc_capable == True).count()
    )
    admin = db.query(EnumerateIamResult).filter(EnumerateIamResult.admin_capable == True).count()
    data_access = (
        db.query(EnumerateIamResult).filter(EnumerateIamResult.data_access_capable == True).count()
    )

    avg_perms = db.query(func.avg(EnumerateIamResult.permission_count)).scalar() or 0.0

    return EnumerateIamSummary(
        total_principals=total,
        privesc_capable=privesc,
        admin_capable=admin,
        data_access_capable=data_access,
        avg_permissions=round(float(avg_perms), 1),
    )


@router.get("/high-risk", response_model=EnumerateIamListResponse)
async def list_high_risk_principals(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List principals with high-risk permissions (privesc, admin, or data access)."""
    query = db.query(EnumerateIamResult).filter(
        (EnumerateIamResult.privesc_capable == True)
        | (EnumerateIamResult.admin_capable == True)
        | (EnumerateIamResult.data_access_capable == True)
    )

    total = query.count()

    results = (
        query.order_by(
            desc(EnumerateIamResult.admin_capable),
            desc(EnumerateIamResult.privesc_capable),
            desc(EnumerateIamResult.permission_count),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return EnumerateIamListResponse(
        results=[EnumerateIamResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{result_id}", response_model=EnumerateIamResultResponse)
async def get_enumerate_iam_result(result_id: int, db: Session = Depends(get_db)):
    """Get a specific enumerate-iam result by ID."""
    result = db.query(EnumerateIamResult).filter(EnumerateIamResult.id == result_id).first()

    if not result:
        raise HTTPException(status_code=404, detail="enumerate-iam result not found")

    return EnumerateIamResultResponse.model_validate(result)


@router.get("/principal/{principal_arn:path}", response_model=EnumerateIamResultResponse)
async def get_result_by_principal(principal_arn: str, db: Session = Depends(get_db)):
    """Get enumerate-iam result for a specific principal ARN."""
    result = (
        db.query(EnumerateIamResult)
        .filter(EnumerateIamResult.principal_arn == principal_arn)
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="No enumeration found for this principal")

    return EnumerateIamResultResponse.model_validate(result)


@router.get("/{result_id}/permissions")
async def get_result_permissions(result_id: int, db: Session = Depends(get_db)):
    """Get detailed permission breakdown for an enumerate-iam result."""
    result = db.query(EnumerateIamResult).filter(EnumerateIamResult.id == result_id).first()

    if not result:
        raise HTTPException(status_code=404, detail="enumerate-iam result not found")

    return {
        "principal_arn": result.principal_arn,
        "principal_name": result.principal_name,
        "total_confirmed": result.permission_count,
        "confirmed_permissions": result.confirmed_permissions or [],
        "denied_permissions": result.denied_permissions or [],
        "error_permissions": result.error_permissions or [],
        "high_risk_permissions": result.high_risk_permissions or [],
        "capabilities": {
            "privesc_capable": result.privesc_capable,
            "admin_capable": result.admin_capable,
            "data_access_capable": result.data_access_capable,
        },
    }


@router.post("/run", response_model=ToolExecutionStartResponse)
async def run_enumerate_iam(request: EnumerateIamRunRequest, db: Session = Depends(get_db)):
    """
    Trigger enumerate-iam permission enumeration.

    Starts an enumerate-iam container to enumerate IAM permissions.
    Results will be stored asynchronously after execution.

    Use GET /api/executions/{execution_id} to check status.
    """
    import re

    # Validate that we have credentials
    if not request.access_key or not request.secret_key:
        raise HTTPException(
            status_code=400, detail="access_key and secret_key are required for enumerate-iam"
        )

    # Validate credential format to prevent command injection
    # AWS access keys: alphanumeric, 16-128 chars
    # AWS secret keys: alphanumeric + /+=, 40 chars typically
    aws_key_pattern = re.compile(r"^[A-Za-z0-9]{16,128}$")
    aws_secret_pattern = re.compile(r"^[A-Za-z0-9/+=]{40,}$")
    aws_token_pattern = re.compile(r"^[A-Za-z0-9/+=]{100,}$")
    aws_region_pattern = re.compile(r"^[a-z]{2}-[a-z]+-\d$")

    if not aws_key_pattern.match(request.access_key):
        raise HTTPException(status_code=400, detail="Invalid AWS access key format")
    if not aws_secret_pattern.match(request.secret_key):
        raise HTTPException(status_code=400, detail="Invalid AWS secret key format")
    if request.session_token and not aws_token_pattern.match(request.session_token):
        raise HTTPException(status_code=400, detail="Invalid AWS session token format")
    if request.region and not aws_region_pattern.match(request.region):
        raise HTTPException(status_code=400, detail="Invalid AWS region format")

    # Build config for tracking
    config = {
        "profile": request.profile,
        "has_credentials": True,
    }

    # Pass credentials via environment variables instead of command line arguments
    # This prevents command injection and avoids exposing secrets in process lists
    environment = {
        "AWS_ACCESS_KEY_ID": request.access_key,
        "AWS_SECRET_ACCESS_KEY": request.secret_key,
    }
    if request.session_token:
        environment["AWS_SESSION_TOKEN"] = request.session_token
    if request.region:
        environment["AWS_DEFAULT_REGION"] = request.region

    # Build command - clone enumerate-iam and run it (credentials from env vars)
    shell_script = """
apt-get update -qq && apt-get install -y -qq git > /dev/null && pip install -q boto3 botocore && git clone --quiet https://github.com/andresriancho/enumerate-iam.git /enumerate-iam 2>/dev/null && python /enumerate-iam/enumerate-iam.py
"""
    command = ["-c", shell_script.strip()]

    # Start the execution with shell entrypoint
    result = await start_tool_execution(
        tool_name="enumerate-iam",
        tool_type=ToolType.ENUMERATE_IAM,
        config=config,
        command=command,
        environment=environment,
        entrypoint="/bin/sh",
        db=db,
    )

    return result
