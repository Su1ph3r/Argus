"""Public Exposures API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import PublicExposure, get_db
from models.schemas import (
    PublicExposureListResponse,
    PublicExposureResponse,
    PublicExposureSummary,
)

router = APIRouter(prefix="/public-exposures", tags=["Public Exposures"])


@router.get("", response_model=PublicExposureListResponse)
@router.get("/", response_model=PublicExposureListResponse)
async def list_public_exposures(
    db: Session = Depends(get_db),
    exposure_type: str | None = Query(None, description="Filter by exposure type"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    cloud_provider: str | None = Query(None, description="Filter by cloud provider"),
    is_internet_exposed: bool | None = Query(None, description="Filter by internet exposure"),
    status: str | None = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List public exposures with optional filters."""
    query = db.query(PublicExposure)

    if exposure_type:
        query = query.filter(PublicExposure.exposure_type == exposure_type)

    if risk_level:
        query = query.filter(PublicExposure.risk_level == risk_level.lower())

    if cloud_provider:
        query = query.filter(PublicExposure.cloud_provider == cloud_provider.lower())

    if is_internet_exposed is not None:
        query = query.filter(PublicExposure.is_internet_exposed == is_internet_exposed)

    if status:
        query = query.filter(PublicExposure.status == status.lower())
    else:
        query = query.filter(PublicExposure.status == "open")

    total = query.count()

    exposures = (
        query.order_by(desc(PublicExposure.last_seen), PublicExposure.risk_level)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PublicExposureListResponse(
        exposures=[PublicExposureResponse.model_validate(e) for e in exposures],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=PublicExposureSummary)
async def get_public_exposure_summary(db: Session = Depends(get_db)):
    """Get summary statistics of public exposures."""
    base_query = db.query(PublicExposure).filter(PublicExposure.status == "open")

    total = base_query.count()

    risk_counts = dict(
        db.query(PublicExposure.risk_level, func.count(PublicExposure.id))
        .filter(PublicExposure.status == "open")
        .group_by(PublicExposure.risk_level)
        .all()
    )

    internet_exposed = base_query.filter(PublicExposure.is_internet_exposed == True).count()

    type_counts = dict(
        db.query(PublicExposure.exposure_type, func.count(PublicExposure.id))
        .filter(PublicExposure.status == "open")
        .group_by(PublicExposure.exposure_type)
        .all()
    )

    provider_counts = dict(
        db.query(PublicExposure.cloud_provider, func.count(PublicExposure.id))
        .filter(PublicExposure.status == "open")
        .group_by(PublicExposure.cloud_provider)
        .all()
    )

    return PublicExposureSummary(
        total=total,
        critical=risk_counts.get("critical", 0),
        high=risk_counts.get("high", 0),
        medium=risk_counts.get("medium", 0),
        low=risk_counts.get("low", 0),
        internet_exposed=internet_exposed,
        by_type={k: v for k, v in type_counts.items() if k},
        by_provider={k: v for k, v in provider_counts.items() if k},
    )


@router.get("/{exposure_id}", response_model=PublicExposureResponse)
async def get_public_exposure(exposure_id: int, db: Session = Depends(get_db)):
    """Get a specific public exposure by ID."""
    exposure = db.query(PublicExposure).filter(PublicExposure.id == exposure_id).first()

    if not exposure:
        raise HTTPException(status_code=404, detail="Public exposure not found")

    return PublicExposureResponse.model_validate(exposure)


@router.patch("/{exposure_id}/status")
async def update_exposure_status(
    exposure_id: int,
    status: str = Query(..., description="New status: open, closed, accepted"),
    db: Session = Depends(get_db),
):
    """Update the status of a public exposure."""
    exposure = db.query(PublicExposure).filter(PublicExposure.id == exposure_id).first()

    if not exposure:
        raise HTTPException(status_code=404, detail="Public exposure not found")

    valid_statuses = ["open", "closed", "accepted"]
    if status.lower() not in valid_statuses:
        raise HTTPException(
            status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}"
        )

    exposure.status = status.lower()
    db.commit()
    db.refresh(exposure)

    return {"message": "Status updated", "exposure_id": exposure_id, "new_status": status.lower()}
