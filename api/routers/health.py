"""Health check endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime

from models.database import get_db
from models.schemas import HealthResponse, DetailedHealthResponse, ServiceStatus

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse)
@router.get("/", response_model=HealthResponse)
async def health_check(db: Session = Depends(get_db)):
    """Basic health check endpoint."""
    db_status = "healthy"

    try:
        # Test database connection
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        database=db_status,
        timestamp=datetime.utcnow(),
        version="1.0.0"
    )


@router.get("/detailed", response_model=DetailedHealthResponse)
async def detailed_health_check(db: Session = Depends(get_db)):
    """Detailed health check with all service statuses."""
    services = []

    # Check PostgreSQL
    try:
        db.execute(text("SELECT 1"))
        services.append(ServiceStatus(name="postgresql", status="healthy"))
    except Exception as e:
        services.append(ServiceStatus(name="postgresql", status="unhealthy", message=str(e)))

    # Check if scans table exists and is accessible
    try:
        result = db.execute(text("SELECT COUNT(*) FROM scans"))
        count = result.scalar()
        services.append(ServiceStatus(
            name="scans_table",
            status="healthy",
            message=f"{count} scans in database"
        ))
    except Exception as e:
        services.append(ServiceStatus(name="scans_table", status="unhealthy", message=str(e)))

    # Check findings table
    try:
        result = db.execute(text("SELECT COUNT(*) FROM findings"))
        count = result.scalar()
        services.append(ServiceStatus(
            name="findings_table",
            status="healthy",
            message=f"{count} findings in database"
        ))
    except Exception as e:
        services.append(ServiceStatus(name="findings_table", status="unhealthy", message=str(e)))

    overall_status = "healthy" if all(s.status == "healthy" for s in services) else "degraded"

    return DetailedHealthResponse(
        status=overall_status,
        services=services,
        timestamp=datetime.utcnow()
    )
