"""
Health check endpoints for Nubicustos API.

Provides:
- Basic health check for load balancers
- Detailed health check with all dependency statuses
- Liveness probe for Kubernetes
- Readiness probe for Kubernetes
- Neo4j and PostgreSQL connectivity checks
"""

import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from config import get_settings
from logging_config import get_logger, get_request_id
from models.database import get_db
from models.schemas import (
    DetailedHealthResponse,
    HealthResponse,
    LivenessResponse,
    ReadinessResponse,
    ServiceStatus,
)

logger = get_logger(__name__)

settings = get_settings()

router: APIRouter = APIRouter(prefix="/health", tags=["Health"])

# Track API startup time for uptime calculation
_startup_time: float | None = None


def set_startup_time() -> None:
    """Set the API startup time. Called during application startup."""
    global _startup_time
    _startup_time = time.time()


def get_uptime_seconds() -> float | None:
    """Get the API uptime in seconds."""
    if _startup_time is None:
        return None
    return time.time() - _startup_time


def check_postgresql(db: Session) -> ServiceStatus:
    """Check PostgreSQL connectivity and return status."""
    start_time = time.time()
    try:
        # Test connection with a simple query
        result = db.execute(text("SELECT version()"))
        version = result.scalar()
        latency_ms = (time.time() - start_time) * 1000

        # Get connection pool stats if available
        pool_size = db.get_bind().pool.size() if hasattr(db.get_bind(), "pool") else None

        return ServiceStatus(
            name="postgresql",
            status="healthy",
            message="Connection successful",
            latency_ms=round(latency_ms, 2),
            details={
                "version": version[:50] if version else None,
                "pool_size": pool_size,
            },
        )
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        logger.error(f"PostgreSQL health check failed: {e}")
        return ServiceStatus(
            name="postgresql",
            status="unhealthy",
            message=str(e)[:200],
            latency_ms=round(latency_ms, 2),
        )


def check_neo4j() -> ServiceStatus:
    """Check Neo4j connectivity and return status."""
    start_time = time.time()

    try:
        # Import neo4j driver - may not be installed in all deployments
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            connection_timeout=5,
        )

        with driver.session() as session:
            result = session.run("RETURN 1 as check")
            result.single()

        driver.close()
        latency_ms = (time.time() - start_time) * 1000

        return ServiceStatus(
            name="neo4j",
            status="healthy",
            message="Connection successful",
            latency_ms=round(latency_ms, 2),
            details={"uri": settings.neo4j_uri},
        )

    except ImportError:
        # Neo4j driver not installed - this is optional
        return ServiceStatus(
            name="neo4j",
            status="unavailable",
            message="Neo4j driver not installed (optional dependency)",
            latency_ms=0,
        )
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        logger.error(f"Neo4j health check failed: {e}")
        return ServiceStatus(
            name="neo4j",
            status="unhealthy",
            message=str(e)[:200],
            latency_ms=round(latency_ms, 2),
        )


def check_database_tables(db: Session) -> ServiceStatus:
    """Check if required database tables exist and are accessible."""
    start_time = time.time()
    try:
        # Check core tables - whitelist validated to prevent SQL injection
        tables_to_check = ["scans", "findings", "assets"]
        allowed_tables = frozenset(["scans", "findings", "assets"])
        table_counts = {}

        for table in tables_to_check:
            # Validate table name against whitelist
            if table not in allowed_tables:
                continue
            result = db.execute(text(f"SELECT COUNT(*) FROM {table}"))
            table_counts[table] = result.scalar()

        latency_ms = (time.time() - start_time) * 1000

        return ServiceStatus(
            name="database_tables",
            status="healthy",
            message="All core tables accessible",
            latency_ms=round(latency_ms, 2),
            details={"table_counts": table_counts},
        )
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        logger.error(f"Database tables check failed: {e}")
        return ServiceStatus(
            name="database_tables",
            status="unhealthy",
            message=str(e)[:200],
            latency_ms=round(latency_ms, 2),
        )


@router.get("", response_model=HealthResponse)
@router.get("/", response_model=HealthResponse)
async def health_check(db: Session = Depends(get_db)):
    """
    Basic health check endpoint.

    Returns a simple health status suitable for load balancer health checks.
    Only checks core database connectivity.
    """
    db_status = "healthy"

    try:
        # Test database connection
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)[:100]}"
        logger.error(f"Health check failed: {e}")

    overall_status = "healthy" if db_status == "healthy" else "degraded"

    return HealthResponse(
        status=overall_status, database=db_status, timestamp=datetime.now(UTC), version="1.0.0"
    )


@router.get("/detailed", response_model=DetailedHealthResponse)
async def detailed_health_check(db: Session = Depends(get_db)):
    """
    Detailed health check with all service statuses.

    Checks:
    - PostgreSQL connectivity and version
    - Neo4j connectivity (if available)
    - Database tables accessibility
    - Returns latency metrics for each check
    """
    services = []

    # Check PostgreSQL
    pg_status = check_postgresql(db)
    services.append(pg_status)

    # Check Neo4j
    neo4j_status = check_neo4j()
    services.append(neo4j_status)

    # Check database tables
    tables_status = check_database_tables(db)
    services.append(tables_status)

    # Determine overall status
    unhealthy_count = sum(1 for s in services if s.status == "unhealthy")
    unavailable_count = sum(1 for s in services if s.status == "unavailable")

    if unhealthy_count > 0:
        if any(s.name == "postgresql" and s.status == "unhealthy" for s in services):
            overall_status = "unhealthy"  # Core dependency failed
        else:
            overall_status = "degraded"
    elif unavailable_count > 0:
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    request_id = get_request_id()

    return DetailedHealthResponse(
        status=overall_status,
        services=services,
        timestamp=datetime.now(UTC),
        uptime_seconds=get_uptime_seconds(),
        request_id=request_id,
    )


@router.get("/live", response_model=LivenessResponse)
async def liveness_probe():
    """
    Kubernetes liveness probe.

    Returns 200 if the application is running.
    This endpoint does not check dependencies - it only confirms the API is responsive.
    """
    return LivenessResponse(status="alive", timestamp=datetime.now(UTC))


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_probe(db: Session = Depends(get_db)):
    """
    Kubernetes readiness probe.

    Checks if the application is ready to accept traffic.
    Verifies all critical dependencies are accessible.
    """
    checks = {}

    # Check PostgreSQL (required)
    try:
        db.execute(text("SELECT 1"))
        checks["postgresql"] = True
    except Exception as e:
        checks["postgresql"] = False
        logger.warning(f"Readiness check - PostgreSQL failed: {e}")

    # Check Neo4j (optional, but logged)
    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            connection_timeout=3,
        )
        with driver.session() as session:
            session.run("RETURN 1")
        driver.close()
        checks["neo4j"] = True
    except ImportError:
        checks["neo4j"] = True  # Optional dependency
    except Exception as e:
        checks["neo4j"] = False
        logger.warning(f"Readiness check - Neo4j failed: {e}")

    # Determine overall readiness (PostgreSQL is required)
    is_ready = checks.get("postgresql", False)

    return ReadinessResponse(
        ready=is_ready,
        status="ready" if is_ready else "not_ready",
        checks=checks,
        timestamp=datetime.now(UTC),
    )
