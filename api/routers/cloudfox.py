"""CloudFox Integration API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import CloudfoxResult, get_db
from models.schemas import (
    CloudfoxResultListResponse,
    CloudfoxResultResponse,
    CloudfoxRunRequest,
    CloudfoxSummary,
    ToolExecutionStartResponse,
)
from routers.executions import start_tool_execution
from services.docker_executor import ToolType

router = APIRouter(prefix="/cloudfox", tags=["CloudFox"])


@router.get("", response_model=CloudfoxResultListResponse)
@router.get("/", response_model=CloudfoxResultListResponse)
async def list_cloudfox_results(
    db: Session = Depends(get_db),
    module_name: str | None = Query(None, description="Filter by module name"),
    finding_category: str | None = Query(None, description="Filter by finding category"),
    cloud_provider: str | None = Query(None, description="Filter by cloud provider"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List CloudFox results with optional filters."""
    query = db.query(CloudfoxResult)

    if module_name:
        query = query.filter(CloudfoxResult.module_name == module_name)

    if finding_category:
        query = query.filter(CloudfoxResult.finding_category == finding_category)

    if cloud_provider:
        query = query.filter(CloudfoxResult.cloud_provider == cloud_provider.lower())

    if risk_level:
        query = query.filter(CloudfoxResult.risk_level == risk_level.lower())

    total = query.count()

    results = (
        query.order_by(desc(CloudfoxResult.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return CloudfoxResultListResponse(
        results=[CloudfoxResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=CloudfoxSummary)
async def get_cloudfox_summary(db: Session = Depends(get_db)):
    """Get summary statistics of CloudFox results."""
    total = db.query(CloudfoxResult).count()

    module_counts = dict(
        db.query(CloudfoxResult.module_name, func.count(CloudfoxResult.id))
        .group_by(CloudfoxResult.module_name)
        .all()
    )

    category_counts = dict(
        db.query(CloudfoxResult.finding_category, func.count(CloudfoxResult.id))
        .group_by(CloudfoxResult.finding_category)
        .all()
    )

    risk_counts = dict(
        db.query(CloudfoxResult.risk_level, func.count(CloudfoxResult.id))
        .group_by(CloudfoxResult.risk_level)
        .all()
    )

    return CloudfoxSummary(
        total_results=total,
        by_module={k: v for k, v in module_counts.items() if k},
        by_category={k: v for k, v in category_counts.items() if k},
        by_risk={k: v for k, v in risk_counts.items() if k},
    )


@router.get("/modules")
async def list_available_modules():
    """List available CloudFox modules."""
    # CloudFox AWS modules
    aws_modules = [
        "all-checks",
        "access-keys",
        "buckets",
        "ecr",
        "eks",
        "elastic-network-interfaces",
        "endpoints",
        "env-vars",
        "filesystems",
        "iam",
        "instances",
        "inventory",
        "lambda",
        "network-ports",
        "outbound-assumed-roles",
        "permissions",
        "principals",
        "ram",
        "resource-trusts",
        "role-trusts",
        "route53",
        "secrets",
        "tags",
        "workloads",
    ]

    return {
        "aws": aws_modules,
        "azure": ["all-checks", "instances", "storage", "rbac"],
        "gcp": ["all-checks", "instances", "storage", "iam"],
    }


@router.get("/{result_id}", response_model=CloudfoxResultResponse)
async def get_cloudfox_result(result_id: int, db: Session = Depends(get_db)):
    """Get a specific CloudFox result by ID."""
    result = db.query(CloudfoxResult).filter(CloudfoxResult.id == result_id).first()

    if not result:
        raise HTTPException(status_code=404, detail="CloudFox result not found")

    return CloudfoxResultResponse.model_validate(result)


@router.get("/module/{module_name}", response_model=CloudfoxResultListResponse)
async def get_results_by_module(
    module_name: str,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """Get all CloudFox results for a specific module."""
    query = db.query(CloudfoxResult).filter(CloudfoxResult.module_name == module_name)

    total = query.count()

    results = (
        query.order_by(desc(CloudfoxResult.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return CloudfoxResultListResponse(
        results=[CloudfoxResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/run", response_model=ToolExecutionStartResponse)
async def run_cloudfox(request: CloudfoxRunRequest, db: Session = Depends(get_db)):
    """
    Trigger CloudFox enumeration.

    Starts a CloudFox container to enumerate AWS/Azure/GCP resources.
    Results will be stored asynchronously after the scan completes.

    Use GET /api/executions/{execution_id} to check status.
    """
    # Build the command based on request parameters
    command = ["cloudfox", "aws"]  # cloudfox binary + AWS provider

    # Add modules
    if request.modules and "all" not in request.modules:
        for module in request.modules:
            command.append(module)
    else:
        command.append("all-checks")

    # Add output directory
    command.extend(["--output", "/reports"])

    # Add profile if specified
    environment = {}
    if request.profile:
        environment["AWS_PROFILE"] = request.profile

    # Build config for tracking
    config = {
        "modules": request.modules,
        "profile": request.profile,
        "regions": request.regions,
    }

    # Start the execution
    result = await start_tool_execution(
        tool_name="cloudfox",
        tool_type=ToolType.CLOUDFOX,
        config=config,
        command=command,
        environment=environment if environment else None,
        db=db,
    )

    return result
