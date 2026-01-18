"""
Scheduled Scanning Service.

This module provides the scheduling infrastructure for recurring security scans
using APScheduler. It integrates with the existing scan orchestration workflow.

Usage:
    from services.scheduler_service import start_scheduler, stop_scheduler

    # In main.py lifespan:
    await start_scheduler()
    # ...
    await stop_scheduler()
"""

import asyncio
import logging
from datetime import datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler | None:
    """Get the global scheduler instance."""
    return _scheduler


async def start_scheduler() -> None:
    """
    Start the APScheduler scheduler.

    This should be called during application startup.
    Loads all enabled schedules from the database and adds them to the scheduler.
    """
    global _scheduler

    if _scheduler is not None:
        logger.warning("Scheduler already running")
        return

    try:
        _scheduler = AsyncIOScheduler()
        _scheduler.start()
        logger.info("Scan scheduler started")

        # Load existing schedules from database
        await _load_schedules_from_db()

    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        _scheduler = None
        raise


async def stop_scheduler() -> None:
    """
    Stop the scheduler gracefully.

    This should be called during application shutdown.
    """
    global _scheduler

    if _scheduler is None:
        return

    try:
        _scheduler.shutdown(wait=True)
        logger.info("Scan scheduler stopped")
    except Exception as e:
        logger.warning(f"Error stopping scheduler: {e}")
    finally:
        _scheduler = None


async def _load_schedules_from_db() -> None:
    """Load all enabled schedules from database and add to scheduler."""
    from models.database import ScanSchedule, get_db

    try:
        db = next(get_db())
        schedules = db.query(ScanSchedule).filter(ScanSchedule.is_enabled == True).all()

        for schedule in schedules:
            await add_schedule_job(schedule)

        logger.info(f"Loaded {len(schedules)} schedules from database")
        db.close()
    except Exception as e:
        logger.error(f"Failed to load schedules from database: {e}")


def _parse_cron_expression(cron_expr: str) -> CronTrigger:
    """
    Parse a cron expression into an APScheduler CronTrigger.

    Supports standard 5-field cron: minute hour day month day_of_week
    """
    parts = cron_expr.strip().split()

    if len(parts) == 5:
        minute, hour, day, month, day_of_week = parts
        return CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
        )
    else:
        raise ValueError(f"Invalid cron expression: {cron_expr}")


async def add_schedule_job(schedule) -> bool:
    """
    Add a schedule to the scheduler.

    Args:
        schedule: ScanSchedule model instance

    Returns:
        True if job was added successfully
    """
    if _scheduler is None:
        logger.warning("Scheduler not running, cannot add job")
        return False

    job_id = str(schedule.schedule_id)

    try:
        # Remove existing job if present
        if _scheduler.get_job(job_id):
            _scheduler.remove_job(job_id)

        # Create trigger based on schedule type
        if schedule.schedule_type == "cron" and schedule.cron_expression:
            trigger = _parse_cron_expression(schedule.cron_expression)
        elif schedule.schedule_type == "interval" and schedule.interval_minutes:
            trigger = IntervalTrigger(minutes=schedule.interval_minutes)
        else:
            logger.warning(f"Invalid schedule configuration for {job_id}")
            return False

        # Add job to scheduler
        _scheduler.add_job(
            execute_scheduled_scan,
            trigger=trigger,
            id=job_id,
            args=[job_id],
            name=f"Scan: {schedule.name}",
            replace_existing=True,
        )

        logger.info(f"Added schedule job: {schedule.name} ({job_id})")
        return True

    except Exception as e:
        logger.error(f"Failed to add schedule job {job_id}: {e}")
        return False


async def remove_schedule_job(schedule_id: str) -> bool:
    """
    Remove a schedule from the scheduler.

    Args:
        schedule_id: UUID of the schedule to remove

    Returns:
        True if job was removed successfully
    """
    if _scheduler is None:
        return False

    try:
        if _scheduler.get_job(schedule_id):
            _scheduler.remove_job(schedule_id)
            logger.info(f"Removed schedule job: {schedule_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to remove schedule job {schedule_id}: {e}")
        return False


async def execute_scheduled_scan(schedule_id: str) -> None:
    """
    Execute a scheduled scan.

    This function is called by the scheduler when a scheduled scan is due.
    It triggers a new scan using the existing scan orchestration.

    Args:
        schedule_id: UUID of the schedule that triggered the scan
    """
    from config import get_settings
    from models.database import ScanSchedule, get_db
    from routers.scans import run_scan_orchestration

    logger.info(f"Executing scheduled scan: {schedule_id}")

    db = None
    try:
        db = next(get_db())

        # Get the schedule
        schedule = (
            db.query(ScanSchedule).filter(ScanSchedule.schedule_id == schedule_id).first()
        )

        if not schedule:
            logger.error(f"Schedule not found: {schedule_id}")
            return

        if not schedule.is_enabled:
            logger.info(f"Schedule is disabled: {schedule_id}")
            return

        # Update last run time
        schedule.last_run_at = datetime.utcnow()
        schedule.run_count += 1
        db.commit()

        # Create a new scan via the orchestration system
        from uuid import uuid4

        from models.database import Scan

        scan = Scan(
            scan_id=uuid4(),
            scan_type=schedule.profile,
            target=schedule.provider or "all",
            tool="multi-tool",
            status="running",
            started_at=datetime.utcnow(),
            scan_metadata={
                "profile": schedule.profile,
                "provider": schedule.provider,
                "scheduled": True,
                "schedule_id": str(schedule.schedule_id),
                "schedule_name": schedule.name,
            },
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Update schedule with scan reference
        schedule.last_scan_id = scan.scan_id
        db.commit()

        # Build Azure credentials if present
        azure_credentials = None
        if schedule.azure_credentials:
            azure_credentials = schedule.azure_credentials

        # Get database URL
        settings = get_settings()

        # Run the scan orchestration in background
        asyncio.create_task(
            run_scan_orchestration(
                str(scan.scan_id),
                schedule.profile,
                None,  # severity_filter
                settings.database_url,
                schedule.aws_profile,
                azure_credentials,
            )
        )

        logger.info(f"Scheduled scan started: {scan.scan_id}")

        # Update schedule status
        schedule.last_run_status = "started"
        schedule.last_error = None
        db.commit()

    except Exception as e:
        logger.error(f"Error executing scheduled scan {schedule_id}: {e}")

        # Update error status in a new session to avoid contamination
        error_db = None
        try:
            error_db = next(get_db())
            schedule = (
                error_db.query(ScanSchedule)
                .filter(ScanSchedule.schedule_id == schedule_id)
                .first()
            )
            if schedule:
                schedule.last_run_status = "failed"
                # Truncate error message to avoid storing sensitive details
                schedule.last_error = str(e)[:500] if str(e) else "Unknown error"
                schedule.error_count += 1
                error_db.commit()
        except Exception:
            pass
        finally:
            if error_db:
                error_db.close()
    finally:
        if db:
            db.close()


def calculate_next_run(schedule) -> datetime | None:
    """
    Calculate the next run time for a schedule.

    Args:
        schedule: ScanSchedule model instance

    Returns:
        Next run datetime or None if cannot be calculated
    """
    if _scheduler is None:
        return None

    job = _scheduler.get_job(str(schedule.schedule_id))
    if job and job.next_run_time:
        return job.next_run_time

    return None


def get_scheduler_status() -> dict:
    """Get scheduler status information."""
    if _scheduler is None:
        return {"running": False, "job_count": 0, "jobs": []}

    jobs = _scheduler.get_jobs()
    return {
        "running": _scheduler.running,
        "job_count": len(jobs),
        "jobs": [
            {
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            }
            for job in jobs
        ],
    }
