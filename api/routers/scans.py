"""Scans endpoints."""
from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional
from uuid import UUID, uuid4
from datetime import datetime
import subprocess
import os
import logging

from models.database import get_db, Scan
from models.schemas import ScanCreate, ScanResponse, ScanListResponse, ScanProfile

router = APIRouter(prefix="/scans", tags=["Scans"])
logger = logging.getLogger(__name__)


def run_scan_task(scan_id: str, profile: str, dry_run: bool, severity_filter: Optional[str]):
    """Background task to run a security scan."""
    try:
        # Build command
        cmd = ["./scripts/run-all-audits.sh"]

        if dry_run:
            cmd.append("--dry-run")

        if profile:
            cmd.extend(["--profile", profile])

        if severity_filter:
            cmd.extend(["--severity", severity_filter])

        # Set environment variables
        env = os.environ.copy()
        env["SCAN_ID"] = scan_id

        logger.info(f"Starting scan {scan_id} with command: {' '.join(cmd)}")

        # Run the scan script
        result = subprocess.run(
            cmd,
            cwd="/app",  # Working directory in container
            env=env,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )

        if result.returncode == 0:
            logger.info(f"Scan {scan_id} completed successfully")
        else:
            logger.error(f"Scan {scan_id} failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        logger.error(f"Scan {scan_id} timed out")
    except Exception as e:
        logger.error(f"Scan {scan_id} error: {str(e)}")


@router.get("", response_model=ScanListResponse)
@router.get("/", response_model=ScanListResponse)
async def list_scans(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status"),
    tool: Optional[str] = Query(None, description="Filter by tool"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page")
):
    """List all scans with optional filters."""
    query = db.query(Scan)

    if status:
        query = query.filter(Scan.status == status)

    if tool:
        query = query.filter(Scan.tool == tool)

    total = query.count()

    scans = query.order_by(desc(Scan.started_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return ScanListResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size
    )


@router.post("", response_model=ScanResponse)
@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Trigger a new security scan."""
    # Create scan record
    scan = Scan(
        scan_id=uuid4(),
        scan_type=scan_request.profile.value,
        target=scan_request.target or "all",
        tool="multi-tool",
        status="pending" if scan_request.dry_run else "running",
        started_at=datetime.utcnow(),
        metadata={
            "profile": scan_request.profile.value,
            "dry_run": scan_request.dry_run,
            "severity_filter": scan_request.severity_filter
        }
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Queue background task to run the scan
    if not scan_request.dry_run:
        background_tasks.add_task(
            run_scan_task,
            str(scan.scan_id),
            scan_request.profile.value,
            scan_request.dry_run,
            scan_request.severity_filter
        )

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: Session = Depends(get_db)
):
    """Get details of a specific scan."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: UUID,
    db: Session = Depends(get_db)
):
    """Get the current status of a scan."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": str(scan.scan_id),
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings": {
            "total": scan.total_findings,
            "critical": scan.critical_findings,
            "high": scan.high_findings,
            "medium": scan.medium_findings,
            "low": scan.low_findings
        }
    }


@router.delete("/{scan_id}")
async def cancel_scan(
    scan_id: UUID,
    db: Session = Depends(get_db)
):
    """Cancel a running scan."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ["pending", "running"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status: {scan.status}"
        )

    scan.status = "cancelled"
    scan.completed_at = datetime.utcnow()
    db.commit()

    return {"message": "Scan cancelled", "scan_id": str(scan_id)}


@router.get("/profiles/list")
async def list_profiles():
    """List available scan profiles."""
    return {
        "profiles": [
            {
                "name": "quick",
                "description": "Fast scan for immediate security posture check",
                "duration_estimate": "5-10 minutes"
            },
            {
                "name": "comprehensive",
                "description": "Full security audit with all tools enabled",
                "duration_estimate": "30-60 minutes"
            },
            {
                "name": "compliance-only",
                "description": "Compliance framework focused scanning",
                "duration_estimate": "15-20 minutes"
            }
        ]
    }
