"""IMDS/Metadata Checker API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import ImdsCheck, get_db
from models.schemas import (
    ImdsCheckListResponse,
    ImdsCheckResponse,
    ImdsCheckSummary,
)

router = APIRouter(prefix="/imds-checks", tags=["IMDS Checks"])


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
