"""Exposed Credentials API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import ExposedCredential, get_db
from models.schemas import (
    CredentialRemediationUpdate,
    ExposedCredentialListResponse,
    ExposedCredentialResponse,
    ExposedCredentialSummary,
)

router = APIRouter(prefix="/exposed-credentials", tags=["Exposed Credentials"])


@router.get("", response_model=ExposedCredentialListResponse)
@router.get("/", response_model=ExposedCredentialListResponse)
async def list_exposed_credentials(
    db: Session = Depends(get_db),
    credential_type: str | None = Query(None, description="Filter by credential type"),
    source_type: str | None = Query(None, description="Filter by source type"),
    cloud_provider: str | None = Query(None, description="Filter by cloud provider"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    remediation_status: str | None = Query(None, description="Filter by remediation status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List exposed credentials with optional filters."""
    query = db.query(ExposedCredential)

    if credential_type:
        query = query.filter(ExposedCredential.credential_type == credential_type)

    if source_type:
        query = query.filter(ExposedCredential.source_type == source_type)

    if cloud_provider:
        query = query.filter(ExposedCredential.cloud_provider == cloud_provider.lower())

    if is_active is not None:
        query = query.filter(ExposedCredential.is_active == is_active)

    if remediation_status:
        query = query.filter(ExposedCredential.remediation_status == remediation_status.lower())
    else:
        query = query.filter(ExposedCredential.remediation_status != "resolved")

    total = query.count()

    credentials = (
        query.order_by(desc(ExposedCredential.last_seen), ExposedCredential.risk_level)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return ExposedCredentialListResponse(
        credentials=[ExposedCredentialResponse.model_validate(c) for c in credentials],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=ExposedCredentialSummary)
async def get_exposed_credential_summary(db: Session = Depends(get_db)):
    """Get summary statistics of exposed credentials."""
    base_query = db.query(ExposedCredential).filter(
        ExposedCredential.remediation_status != "resolved"
    )

    total = base_query.count()
    active = base_query.filter(ExposedCredential.is_active == True).count()

    type_counts = dict(
        db.query(ExposedCredential.credential_type, func.count(ExposedCredential.id))
        .filter(ExposedCredential.remediation_status != "resolved")
        .group_by(ExposedCredential.credential_type)
        .all()
    )

    source_counts = dict(
        db.query(ExposedCredential.source_type, func.count(ExposedCredential.id))
        .filter(ExposedCredential.remediation_status != "resolved")
        .group_by(ExposedCredential.source_type)
        .all()
    )

    provider_counts = dict(
        db.query(ExposedCredential.cloud_provider, func.count(ExposedCredential.id))
        .filter(ExposedCredential.remediation_status != "resolved")
        .group_by(ExposedCredential.cloud_provider)
        .all()
    )

    return ExposedCredentialSummary(
        total=total,
        active=active,
        by_type={k: v for k, v in type_counts.items() if k},
        by_source={k: v for k, v in source_counts.items() if k},
        by_provider={k: v for k, v in provider_counts.items() if k},
    )


@router.get("/{credential_id}", response_model=ExposedCredentialResponse)
async def get_exposed_credential(credential_id: int, db: Session = Depends(get_db)):
    """Get a specific exposed credential by ID."""
    credential = db.query(ExposedCredential).filter(ExposedCredential.id == credential_id).first()

    if not credential:
        raise HTTPException(status_code=404, detail="Exposed credential not found")

    return ExposedCredentialResponse.model_validate(credential)


@router.patch("/{credential_id}/remediation", response_model=ExposedCredentialResponse)
async def update_credential_remediation(
    credential_id: int, update: CredentialRemediationUpdate, db: Session = Depends(get_db)
):
    """Update the remediation status of an exposed credential."""
    credential = db.query(ExposedCredential).filter(ExposedCredential.id == credential_id).first()

    if not credential:
        raise HTTPException(status_code=404, detail="Exposed credential not found")

    valid_statuses = ["pending", "in_progress", "resolved", "accepted"]
    if update.remediation_status.lower() not in valid_statuses:
        raise HTTPException(
            status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}"
        )

    credential.remediation_status = update.remediation_status.lower()
    if update.remediation_notes:
        credential.remediation_notes = update.remediation_notes

    db.commit()
    db.refresh(credential)

    return ExposedCredentialResponse.model_validate(credential)
