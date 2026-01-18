"""
Scheduled Scans API Endpoints.

This module provides endpoints for managing scheduled/recurring security scans.

Endpoints:
    GET /schedules - List all schedules
    POST /schedules - Create a new schedule
    GET /schedules/{schedule_id} - Get schedule details
    PATCH /schedules/{schedule_id} - Update a schedule
    DELETE /schedules/{schedule_id} - Delete a schedule
    POST /schedules/{schedule_id}/trigger - Trigger immediately
    GET /schedules/status - Get scheduler status
"""

import logging
from datetime import datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc
from sqlalchemy.orm import Session

from models.database import ScanSchedule, get_db
from services.scheduler_service import (
    add_schedule_job,
    calculate_next_run,
    execute_scheduled_scan,
    get_scheduler_status,
    remove_schedule_job,
)

router = APIRouter(prefix="/schedules", tags=["Scheduled Scans"])
logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Schemas
# =============================================================================


class ScheduleCreate(BaseModel):
    """Request schema for creating a schedule."""

    name: str = Field(min_length=1, max_length=128, description="Schedule name")
    description: str | None = Field(default=None, max_length=512)
    profile: str = Field(max_length=64, description="Scan profile to use")
    provider: str | None = Field(default=None, max_length=32)
    aws_profile: str | None = Field(
        default=None, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"
    )
    azure_credentials: dict | None = None
    schedule_type: str = Field(default="cron", pattern=r"^(cron|interval)$")
    cron_expression: str | None = Field(
        default=None,
        max_length=128,
        description="5-field cron: minute hour day month day_of_week",
    )
    interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    is_enabled: bool = True

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v, info):
        """Validate cron expression has 5 parts."""
        if v is None:
            return v
        parts = v.strip().split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 parts: minute hour day month day_of_week")
        return v

    @field_validator("interval_minutes")
    @classmethod
    def validate_interval(cls, v, info):
        """Validate interval is within bounds."""
        if v is not None and v < 5:
            raise ValueError("Interval must be at least 5 minutes")
        return v


class ScheduleUpdate(BaseModel):
    """Request schema for updating a schedule."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    profile: str | None = Field(default=None, max_length=64)
    provider: str | None = Field(default=None, max_length=32)
    aws_profile: str | None = Field(
        default=None, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"
    )
    azure_credentials: dict | None = None
    schedule_type: str | None = Field(default=None, pattern=r"^(cron|interval)$")
    cron_expression: str | None = None
    interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    is_enabled: bool | None = None


class ScheduleResponse(BaseModel):
    """Response schema for schedule details."""

    id: int
    schedule_id: UUID
    name: str
    description: str | None
    profile: str
    provider: str | None
    aws_profile: str | None
    schedule_type: str
    cron_expression: str | None
    interval_minutes: int | None
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_run_status: str | None
    last_scan_id: UUID | None
    is_enabled: bool
    run_count: int
    error_count: int
    last_error: str | None
    created_at: datetime | None
    updated_at: datetime | None

    class Config:
        from_attributes = True


class ScheduleListResponse(BaseModel):
    """Response schema for listing schedules."""

    schedules: list[ScheduleResponse]
    total: int
    page: int
    page_size: int


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/status")
async def get_status():
    """
    Get scheduler status.

    Returns information about the scheduler including running status,
    job count, and details about scheduled jobs.
    """
    return get_scheduler_status()


@router.get("", response_model=ScheduleListResponse)
@router.get("/", response_model=ScheduleListResponse)
async def list_schedules(
    db: Session = Depends(get_db),
    is_enabled: bool | None = Query(None, description="Filter by enabled status"),
    profile: str | None = Query(None, description="Filter by profile"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
):
    """
    List all scan schedules.

    Returns paginated list of schedules with optional filtering.
    """
    query = db.query(ScanSchedule)

    if is_enabled is not None:
        query = query.filter(ScanSchedule.is_enabled == is_enabled)

    if profile:
        query = query.filter(ScanSchedule.profile == profile)

    total = query.count()

    schedules = (
        query.order_by(desc(ScanSchedule.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    # Calculate next run times
    for schedule in schedules:
        schedule.next_run_at = calculate_next_run(schedule)

    return ScheduleListResponse(
        schedules=[ScheduleResponse.model_validate(s) for s in schedules],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=ScheduleResponse, status_code=201)
@router.post("/", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    schedule_data: ScheduleCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new scan schedule.

    Creates a schedule record and adds it to the scheduler if enabled.
    """
    # Validate that either cron or interval is provided
    if schedule_data.schedule_type == "cron" and not schedule_data.cron_expression:
        raise HTTPException(
            status_code=400,
            detail="cron_expression is required for schedule_type=cron",
        )
    if schedule_data.schedule_type == "interval" and not schedule_data.interval_minutes:
        raise HTTPException(
            status_code=400,
            detail="interval_minutes is required for schedule_type=interval",
        )

    # Create schedule record
    schedule = ScanSchedule(
        schedule_id=uuid4(),
        name=schedule_data.name,
        description=schedule_data.description,
        profile=schedule_data.profile,
        provider=schedule_data.provider,
        aws_profile=schedule_data.aws_profile,
        azure_credentials=schedule_data.azure_credentials,
        schedule_type=schedule_data.schedule_type,
        cron_expression=schedule_data.cron_expression,
        interval_minutes=schedule_data.interval_minutes,
        is_enabled=schedule_data.is_enabled,
    )

    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    # Add to scheduler if enabled
    if schedule.is_enabled:
        await add_schedule_job(schedule)
        schedule.next_run_at = calculate_next_run(schedule)

    logger.info(f"Created schedule: {schedule.name} ({schedule.schedule_id})")

    return ScheduleResponse.model_validate(schedule)


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    db: Session = Depends(get_db),
):
    """
    Get schedule details.

    Returns full details of a specific schedule including next run time.
    """
    schedule = (
        db.query(ScanSchedule).filter(ScanSchedule.schedule_id == schedule_id).first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule.next_run_at = calculate_next_run(schedule)

    return ScheduleResponse.model_validate(schedule)


@router.patch("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    schedule_data: ScheduleUpdate,
    db: Session = Depends(get_db),
):
    """
    Update a schedule.

    Updates schedule configuration and refreshes the scheduler job.
    """
    schedule = (
        db.query(ScanSchedule).filter(ScanSchedule.schedule_id == schedule_id).first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Update fields
    for field, value in schedule_data.model_dump(exclude_unset=True).items():
        setattr(schedule, field, value)

    schedule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(schedule)

    # Update scheduler job
    if schedule.is_enabled:
        await add_schedule_job(schedule)
    else:
        await remove_schedule_job(str(schedule_id))

    schedule.next_run_at = calculate_next_run(schedule)

    logger.info(f"Updated schedule: {schedule.name} ({schedule.schedule_id})")

    return ScheduleResponse.model_validate(schedule)


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: UUID,
    db: Session = Depends(get_db),
):
    """
    Delete a schedule.

    Removes the schedule from the database and scheduler.
    """
    schedule = (
        db.query(ScanSchedule).filter(ScanSchedule.schedule_id == schedule_id).first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Remove from scheduler
    await remove_schedule_job(str(schedule_id))

    # Delete from database
    db.delete(schedule)
    db.commit()

    logger.info(f"Deleted schedule: {schedule.name} ({schedule_id})")

    return {"message": "Schedule deleted", "schedule_id": str(schedule_id)}


@router.post("/{schedule_id}/trigger")
async def trigger_schedule(
    schedule_id: UUID,
    db: Session = Depends(get_db),
):
    """
    Trigger a scheduled scan immediately.

    Runs the scheduled scan without waiting for the next scheduled time.
    Does not affect the regular schedule.
    """
    schedule = (
        db.query(ScanSchedule).filter(ScanSchedule.schedule_id == schedule_id).first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Execute the scan
    import asyncio

    asyncio.create_task(execute_scheduled_scan(str(schedule_id)))

    return {
        "message": "Scan triggered",
        "schedule_id": str(schedule_id),
        "schedule_name": schedule.name,
    }
