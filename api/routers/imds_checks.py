"""IMDS/Metadata Checker API endpoints."""

import asyncio
import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import ImdsCheck, ToolExecution, get_db
from models.schemas import (
    ImdsCheckListResponse,
    ImdsCheckResponse,
    ImdsCheckSummary,
    ToolExecutionStartResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/imds-checks", tags=["IMDS Checks"])


class ImdsCheckScanRequest(BaseModel):
    """Request schema for IMDS scan."""

    profile: str | None = None
    regions: list[str] | None = None
    access_key: str | None = None
    secret_key: str | None = None
    session_token: str | None = None


async def _run_imds_scan(
    execution_id: str,
    profile: str | None,
    regions: list[str] | None,
    access_key: str | None,
    secret_key: str | None,
    session_token: str | None,
    db_url: str,
):
    """
    Background task to scan EC2 instances for IMDS vulnerabilities.

    Queries AWS for EC2 instances and checks their IMDS configuration.
    """
    import boto3
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        # Update execution to running
        execution = (
            db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()
        )
        if execution:
            execution.status = "running"
            execution.started_at = datetime.utcnow()
            db.commit()

        # Set up boto3 session with credentials
        session_kwargs = {}
        if access_key and secret_key:
            session_kwargs["aws_access_key_id"] = access_key
            session_kwargs["aws_secret_access_key"] = secret_key
            if session_token:
                session_kwargs["aws_session_token"] = session_token
        elif profile:
            session_kwargs["profile_name"] = profile

        session = boto3.Session(**session_kwargs)

        # Get regions to scan
        if regions:
            target_regions = regions
        else:
            # Get all enabled regions
            ec2_client = session.client("ec2", region_name="us-east-1")
            try:
                response = ec2_client.describe_regions(
                    Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
                )
                target_regions = [r["RegionName"] for r in response["Regions"]]
            except Exception as e:
                logger.warning(f"Could not list regions, using defaults: {e}")
                target_regions = ["us-east-1", "us-west-2", "eu-west-1"]

        # Get account ID
        sts = session.client("sts")
        try:
            account_id = sts.get_caller_identity()["Account"]
        except Exception:
            account_id = "unknown"

        instances_checked = 0
        vulnerabilities_found = 0

        for region in target_regions:
            try:
                ec2 = session.client("ec2", region_name=region)

                # Describe instances
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate():
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            instance_id = instance["InstanceId"]
                            instance_state = instance.get("State", {}).get("Name", "")

                            # Skip terminated instances
                            if instance_state == "terminated":
                                continue

                            # Get instance name from tags
                            instance_name = None
                            for tag in instance.get("Tags", []):
                                if tag["Key"] == "Name":
                                    instance_name = tag["Value"]
                                    break

                            # Get IMDS configuration
                            metadata_options = instance.get("MetadataOptions", {})
                            http_endpoint = metadata_options.get("HttpEndpoint", "enabled")
                            http_tokens = metadata_options.get("HttpTokens", "optional")
                            hop_limit = metadata_options.get("HttpPutResponseHopLimit", 1)

                            # Determine IMDS configuration
                            imds_v1_enabled = http_tokens != "required"
                            http_tokens_required = http_tokens == "required"
                            http_endpoint_enabled = http_endpoint == "enabled"

                            # SSRF vulnerability analysis
                            # High risk if IMDSv1 is enabled and hop limit > 1
                            ssrf_vulnerable = imds_v1_enabled and hop_limit > 1

                            # Container exposure - check if instance might be running containers
                            # and has permissive IMDS settings
                            container_exposure = False
                            ecs_task_role_exposed = False
                            eks_pod_identity_exposed = False

                            # Check for ECS/EKS indicators in tags
                            for tag in instance.get("Tags", []):
                                key = tag["Key"].lower()
                                if "ecs" in key or "container" in key:
                                    if imds_v1_enabled:
                                        container_exposure = True
                                        ecs_task_role_exposed = True
                                if "eks" in key or "kubernetes" in key:
                                    if imds_v1_enabled:
                                        container_exposure = True
                                        eks_pod_identity_exposed = True

                            # Calculate risk level
                            if imds_v1_enabled and ssrf_vulnerable:
                                risk_level = "critical"
                                vulnerabilities_found += 1
                            elif imds_v1_enabled:
                                risk_level = "high"
                                vulnerabilities_found += 1
                            elif container_exposure:
                                risk_level = "medium"
                                vulnerabilities_found += 1
                            elif hop_limit > 2:
                                risk_level = "low"
                            else:
                                risk_level = "info"

                            # Create check record
                            check_id = f"imds-{instance_id}-{int(datetime.utcnow().timestamp())}"

                            # Check if already exists
                            existing = (
                                db.query(ImdsCheck)
                                .filter(ImdsCheck.instance_id == instance_id)
                                .first()
                            )

                            if existing:
                                # Update existing record
                                existing.imds_v1_enabled = imds_v1_enabled
                                existing.http_tokens_required = http_tokens_required
                                existing.http_endpoint_enabled = http_endpoint_enabled
                                existing.imds_hop_limit = hop_limit
                                existing.ssrf_vulnerable = ssrf_vulnerable
                                existing.container_credential_exposure = container_exposure
                                existing.ecs_task_role_exposed = ecs_task_role_exposed
                                existing.eks_pod_identity_exposed = eks_pod_identity_exposed
                                existing.risk_level = risk_level
                                existing.instance_name = instance_name
                                existing.updated_at = datetime.utcnow()
                            else:
                                # Create new record
                                imds_check = ImdsCheck(
                                    check_id=check_id,
                                    cloud_provider="aws",
                                    account_id=account_id,
                                    region=region,
                                    instance_id=instance_id,
                                    instance_name=instance_name,
                                    imds_version="v2" if http_tokens_required else "v1",
                                    imds_v1_enabled=imds_v1_enabled,
                                    imds_hop_limit=hop_limit,
                                    http_endpoint_enabled=http_endpoint_enabled,
                                    http_tokens_required=http_tokens_required,
                                    ssrf_vulnerable=ssrf_vulnerable,
                                    container_credential_exposure=container_exposure,
                                    ecs_task_role_exposed=ecs_task_role_exposed,
                                    eks_pod_identity_exposed=eks_pod_identity_exposed,
                                    risk_level=risk_level,
                                    vulnerability_details={
                                        "http_endpoint": http_endpoint,
                                        "http_tokens": http_tokens,
                                        "hop_limit": hop_limit,
                                        "instance_state": instance_state,
                                    },
                                )
                                db.add(imds_check)

                            instances_checked += 1

                    db.commit()

            except Exception as e:
                logger.error(f"Error scanning region {region}: {e}")
                continue

        # Update execution to completed
        execution = (
            db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()
        )
        if execution:
            execution.status = "completed"
            execution.completed_at = datetime.utcnow()
            execution.exit_code = 0
            execution.config = {
                **(execution.config or {}),
                "instances_checked": instances_checked,
                "vulnerabilities_found": vulnerabilities_found,
                "regions_scanned": target_regions,
            }
            db.commit()

        logger.info(
            f"IMDS scan {execution_id} completed: {instances_checked} instances, "
            f"{vulnerabilities_found} vulnerabilities"
        )

    except Exception as e:
        logger.error(f"IMDS scan {execution_id} failed: {e}")
        execution = (
            db.query(ToolExecution).filter(ToolExecution.execution_id == execution_id).first()
        )
        if execution:
            execution.status = "failed"
            execution.completed_at = datetime.utcnow()
            execution.error_message = str(e)[:2000]
            db.commit()
    finally:
        db.close()


@router.post("/scan", response_model=ToolExecutionStartResponse)
async def run_imds_scan(
    request: ImdsCheckScanRequest = None,
    db: Session = Depends(get_db),
):
    """
    Trigger an IMDS vulnerability scan.

    Scans EC2 instances across specified regions and checks their IMDS configuration
    for potential vulnerabilities including:
    - IMDSv1 enabled (allows unauthenticated metadata access)
    - High hop limit (increases SSRF risk)
    - Container credential exposure
    - ECS/EKS role exposure

    Use GET /api/executions/{execution_id} to check status.
    """
    from config import get_settings

    if request is None:
        request = ImdsCheckScanRequest()

    execution_id = str(uuid.uuid4())[:12]

    # Create execution record
    execution = ToolExecution(
        execution_id=execution_id,
        tool_name="imds-checker",
        tool_type="imds-checker",
        status="pending",
        config={
            "profile": request.profile,
            "regions": request.regions,
            "has_credentials": bool(request.access_key and request.secret_key),
        },
        created_at=datetime.utcnow(),
    )
    db.add(execution)
    db.commit()

    # Start background task
    settings = get_settings()

    asyncio.create_task(
        _run_imds_scan(
            execution_id=execution_id,
            profile=request.profile,
            regions=request.regions,
            access_key=request.access_key,
            secret_key=request.secret_key,
            session_token=request.session_token,
            db_url=settings.database_url,
        )
    )

    return ToolExecutionStartResponse(
        execution_id=execution_id,
        tool_name="imds-checker",
        status="running",
        message="IMDS scan started successfully",
    )


@router.get("", response_model=ImdsCheckListResponse)
@router.get("/", response_model=ImdsCheckListResponse)
async def list_imds_checks(
    db: Session = Depends(get_db),
    cloud_provider: str | None = Query(None, description="Filter by cloud provider"),
    region: str | None = Query(None, description="Filter by region"),
    imds_v1_enabled: bool | None = Query(None, description="Filter by IMDSv1 status"),
    ssrf_vulnerable: bool | None = Query(None, description="Filter by SSRF vulnerability"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List IMDS checks with optional filters."""
    query = db.query(ImdsCheck)

    if cloud_provider:
        query = query.filter(ImdsCheck.cloud_provider == cloud_provider.lower())

    if region:
        query = query.filter(ImdsCheck.region == region)

    if imds_v1_enabled is not None:
        query = query.filter(ImdsCheck.imds_v1_enabled == imds_v1_enabled)

    if ssrf_vulnerable is not None:
        query = query.filter(ImdsCheck.ssrf_vulnerable == ssrf_vulnerable)

    if risk_level:
        query = query.filter(ImdsCheck.risk_level == risk_level.lower())

    total = query.count()

    checks = (
        query.order_by(desc(ImdsCheck.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return ImdsCheckListResponse(
        checks=[ImdsCheckResponse.model_validate(c) for c in checks],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=ImdsCheckSummary)
async def get_imds_summary(db: Session = Depends(get_db)):
    """Get summary statistics of IMDS checks."""
    total = db.query(ImdsCheck).count()
    v1_enabled = db.query(ImdsCheck).filter(ImdsCheck.imds_v1_enabled == True).count()
    ssrf_vuln = db.query(ImdsCheck).filter(ImdsCheck.ssrf_vulnerable == True).count()
    container_exp = (
        db.query(ImdsCheck).filter(ImdsCheck.container_credential_exposure == True).count()
    )

    region_counts = dict(
        db.query(ImdsCheck.region, func.count(ImdsCheck.id)).group_by(ImdsCheck.region).all()
    )

    return ImdsCheckSummary(
        total_instances=total,
        imds_v1_enabled=v1_enabled,
        ssrf_vulnerable=ssrf_vuln,
        container_exposed=container_exp,
        by_region={k: v for k, v in region_counts.items() if k},
    )


@router.get("/vulnerable", response_model=ImdsCheckListResponse)
async def list_vulnerable_instances(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List instances with IMDS vulnerabilities (v1 enabled, SSRF, or container exposure)."""
    query = db.query(ImdsCheck).filter(
        (ImdsCheck.imds_v1_enabled == True)
        | (ImdsCheck.ssrf_vulnerable == True)
        | (ImdsCheck.container_credential_exposure == True)
        | (ImdsCheck.ecs_task_role_exposed == True)
        | (ImdsCheck.eks_pod_identity_exposed == True)
    )

    total = query.count()

    checks = (
        query.order_by(desc(ImdsCheck.risk_level), desc(ImdsCheck.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return ImdsCheckListResponse(
        checks=[ImdsCheckResponse.model_validate(c) for c in checks],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{check_id}", response_model=ImdsCheckResponse)
async def get_imds_check(check_id: int, db: Session = Depends(get_db)):
    """Get a specific IMDS check by ID."""
    check = db.query(ImdsCheck).filter(ImdsCheck.id == check_id).first()

    if not check:
        raise HTTPException(status_code=404, detail="IMDS check not found")

    return ImdsCheckResponse.model_validate(check)


@router.get("/instance/{instance_id}", response_model=ImdsCheckResponse)
async def get_imds_by_instance(instance_id: str, db: Session = Depends(get_db)):
    """Get IMDS check for a specific instance ID."""
    check = db.query(ImdsCheck).filter(ImdsCheck.instance_id == instance_id).first()

    if not check:
        raise HTTPException(status_code=404, detail="IMDS check not found for this instance")

    return ImdsCheckResponse.model_validate(check)


@router.patch("/{check_id}/remediation")
async def update_imds_remediation(
    check_id: int,
    status: str = Query(..., description="New status: pending, in_progress, resolved"),
    db: Session = Depends(get_db),
):
    """Update the remediation status of an IMDS check."""
    check = db.query(ImdsCheck).filter(ImdsCheck.id == check_id).first()

    if not check:
        raise HTTPException(status_code=404, detail="IMDS check not found")

    valid_statuses = ["pending", "in_progress", "resolved"]
    if status.lower() not in valid_statuses:
        raise HTTPException(
            status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}"
        )

    check.remediation_status = status.lower()
    db.commit()

    return {
        "message": "Remediation status updated",
        "check_id": check_id,
        "new_status": status.lower(),
    }
