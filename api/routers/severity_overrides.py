"""Severity Override API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from models.database import Finding, SeverityOverride, get_db
from models.schemas import (
    SeverityOverrideApproval,
    SeverityOverrideCreate,
    SeverityOverrideListResponse,
    SeverityOverrideResponse,
)

router = APIRouter(prefix="/severity-overrides", tags=["Severity Overrides"])


@router.get("", response_model=SeverityOverrideListResponse)
@router.get("/", response_model=SeverityOverrideListResponse)
async def list_severity_overrides(
    db: Session = Depends(get_db),
    approval_status: str | None = Query(None, description="Filter by approval status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List severity overrides with optional filters."""
    query = db.query(SeverityOverride)

    if approval_status:
        query = query.filter(SeverityOverride.approval_status == approval_status.lower())

    total = query.count()

    overrides = (
        query.order_by(desc(SeverityOverride.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return SeverityOverrideListResponse(
        overrides=[SeverityOverrideResponse.model_validate(o) for o in overrides],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=SeverityOverrideResponse)
@router.post("/", response_model=SeverityOverrideResponse)
async def create_severity_override(override: SeverityOverrideCreate, db: Session = Depends(get_db)):
    """Create a new severity override for a finding."""
    # Check if finding exists
    finding = db.query(Finding).filter(Finding.id == override.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Check if override already exists for this finding
    existing = (
        db.query(SeverityOverride)
        .filter(SeverityOverride.finding_id == override.finding_id)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Override already exists for this finding. Delete existing override first.",
        )

    # Validate severity values
    valid_severities = ["critical", "high", "medium", "low", "info"]
    if override.new_severity.lower() not in valid_severities:
        raise HTTPException(
            status_code=400, detail=f"Invalid severity. Must be one of: {valid_severities}"
        )

    # Create override
    db_override = SeverityOverride(
        finding_id=override.finding_id,
        original_severity=finding.severity,
        new_severity=override.new_severity.lower(),
        justification=override.justification,
        created_by=override.created_by,
        expires_at=override.expires_at,
        override_type="manual",
        approval_status="pending",
    )

    db.add(db_override)
    db.commit()
    db.refresh(db_override)

    return SeverityOverrideResponse.model_validate(db_override)


@router.get("/{override_id}", response_model=SeverityOverrideResponse)
async def get_severity_override(override_id: int, db: Session = Depends(get_db)):
    """Get a specific severity override by ID."""
    override = db.query(SeverityOverride).filter(SeverityOverride.id == override_id).first()

    if not override:
        raise HTTPException(status_code=404, detail="Severity override not found")

    return SeverityOverrideResponse.model_validate(override)


@router.get("/by-finding/{finding_id}", response_model=SeverityOverrideResponse)
async def get_override_by_finding(finding_id: int, db: Session = Depends(get_db)):
    """Get the severity override for a specific finding."""
    override = db.query(SeverityOverride).filter(SeverityOverride.finding_id == finding_id).first()

    if not override:
        raise HTTPException(status_code=404, detail="No override found for this finding")

    return SeverityOverrideResponse.model_validate(override)


@router.post("/{override_id}/approve", response_model=SeverityOverrideResponse)
async def approve_severity_override(
    override_id: int, approval: SeverityOverrideApproval, db: Session = Depends(get_db)
):
    """Approve or reject a severity override."""
    override = db.query(SeverityOverride).filter(SeverityOverride.id == override_id).first()

    if not override:
        raise HTTPException(status_code=404, detail="Severity override not found")

    if override.approval_status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Override already processed with status: {override.approval_status}",
        )

    override.approved_by = approval.approved_by
    override.approval_status = "approved" if approval.approved else "rejected"

    # If approved, update the finding's effective severity (could be in a separate field)
    if approval.approved:
        finding = db.query(Finding).filter(Finding.id == override.finding_id).first()
        if finding:
            # Store original if not already stored, then update
            finding.severity = override.new_severity

    db.commit()
    db.refresh(override)

    return SeverityOverrideResponse.model_validate(override)


@router.delete("/{override_id}")
async def delete_severity_override(override_id: int, db: Session = Depends(get_db)):
    """Delete a severity override."""
    override = db.query(SeverityOverride).filter(SeverityOverride.id == override_id).first()

    if not override:
        raise HTTPException(status_code=404, detail="Severity override not found")

    # If was approved, restore original severity
    if override.approval_status == "approved":
        finding = db.query(Finding).filter(Finding.id == override.finding_id).first()
        if finding:
            finding.severity = override.original_severity

    db.delete(override)
    db.commit()

    return {"message": "Severity override deleted", "override_id": override_id}
