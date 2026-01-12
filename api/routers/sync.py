"""
Neo4j Synchronization endpoints.

Provides REST API endpoints for:
- Checking sync status between PostgreSQL and Neo4j
- Triggering manual synchronization
- Viewing sync health and discrepancies
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models.database import get_db
from services.neo4j_sync import get_neo4j_sync_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sync", tags=["Sync"])


# ============================================================================
# Pydantic Schemas for API
# ============================================================================


class SyncDirectionEnum(str, Enum):
    """Direction of sync operation for API."""

    neo4j_to_pg = "neo4j_to_pg"
    pg_to_neo4j = "pg_to_neo4j"
    bidirectional = "bidirectional"


class SyncStatusResponse(BaseModel):
    """Response model for sync status check."""

    neo4j_connected: bool = Field(description="Whether Neo4j is reachable")
    postgres_connected: bool = Field(description="Whether PostgreSQL is reachable")
    neo4j_asset_count: int = Field(description="Number of assets in Neo4j")
    postgres_asset_count: int = Field(description="Number of assets in PostgreSQL")
    count_mismatch: int = Field(description="Absolute difference in asset counts")
    missing_in_postgres: int = Field(description="Assets in Neo4j but not in PostgreSQL")
    missing_in_neo4j: int = Field(description="Assets in PostgreSQL but not in Neo4j")
    in_sync: bool = Field(description="Whether databases are in sync")
    last_sync: datetime | None = Field(default=None, description="Last sync timestamp")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")


class SyncResultResponse(BaseModel):
    """Response model for sync operation result."""

    success: bool
    direction: str
    assets_synced: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    assets_deleted: int = 0
    findings_propagated: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    duration_ms: int = 0
    timestamp: datetime


class SyncRequest(BaseModel):
    """Request model for triggering sync."""

    direction: SyncDirectionEnum = Field(
        default=SyncDirectionEnum.bidirectional, description="Direction of sync operation"
    )
    mark_stale: bool = Field(default=False, description="Mark assets not in Neo4j as inactive")


class SyncHealthResponse(BaseModel):
    """Response model for sync health check."""

    status: str = Field(description="Overall sync health: healthy, degraded, unhealthy")
    neo4j_status: str
    postgres_status: str
    sync_lag: int = Field(description="Estimated sync lag in minutes")
    issues: list[str] = Field(default_factory=list, description="List of detected issues")
    recommendations: list[str] = Field(default_factory=list, description="Recommended actions")


class DiscrepancyResponse(BaseModel):
    """Response model for discrepancy details."""

    total_discrepancies: int
    missing_in_postgres: list[str] = Field(description="Asset IDs missing in PostgreSQL")
    missing_in_neo4j: list[str] = Field(description="Asset IDs missing in Neo4j")
    by_type: dict[str, int] = Field(default_factory=dict, description="Discrepancies by asset type")


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/status", response_model=SyncStatusResponse)
async def get_sync_status(db: Session = Depends(get_db)):
    """
    Get current synchronization status between PostgreSQL and Neo4j.

    Returns:
    - Connection status for both databases
    - Asset counts in each database
    - Count of discrepancies
    - Whether databases are considered in sync
    """
    try:
        sync_service = get_neo4j_sync_service()
        status = sync_service.get_sync_status(db)

        # Databases are in sync if count mismatch is within tolerance
        in_sync = (
            status.neo4j_connected
            and status.postgres_connected
            and status.count_mismatch < 10  # Small tolerance for timing
        )

        return SyncStatusResponse(
            neo4j_connected=status.neo4j_connected,
            postgres_connected=status.postgres_connected,
            neo4j_asset_count=status.neo4j_asset_count,
            postgres_asset_count=status.postgres_asset_count,
            count_mismatch=status.count_mismatch,
            missing_in_postgres=status.missing_in_postgres,
            missing_in_neo4j=status.missing_in_neo4j,
            in_sync=in_sync,
            last_sync=status.last_sync,
            details=status.details,
        )
    except Exception as e:
        logger.error(f"Error getting sync status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get sync status: {str(e)}")


@router.get("/health", response_model=SyncHealthResponse)
async def get_sync_health(db: Session = Depends(get_db)):
    """
    Get sync health status with recommendations.

    Analyzes sync status and provides:
    - Overall health status (healthy, degraded, unhealthy)
    - Specific issues detected
    - Recommendations for resolving issues
    """
    try:
        sync_service = get_neo4j_sync_service()
        status = sync_service.get_sync_status(db)

        issues = []
        recommendations = []
        overall_status = "healthy"

        # Check Neo4j connection
        if not status.neo4j_connected:
            issues.append("Neo4j is not reachable")
            recommendations.append("Check Neo4j container status: docker-compose ps neo4j")
            recommendations.append("Verify Neo4j credentials in environment")
            overall_status = "unhealthy"

        # Check PostgreSQL connection
        if not status.postgres_connected:
            issues.append("PostgreSQL is not reachable")
            recommendations.append(
                "Check PostgreSQL container status: docker-compose ps postgresql"
            )
            overall_status = "unhealthy"

        # Check count mismatch
        if status.count_mismatch > 100:
            issues.append(f"Significant count mismatch: {status.count_mismatch} assets differ")
            recommendations.append(
                "Run full sync: POST /api/sync/trigger with bidirectional direction"
            )
            if overall_status == "healthy":
                overall_status = "degraded"
        elif status.count_mismatch > 10:
            issues.append(f"Minor count mismatch: {status.count_mismatch} assets differ")
            if overall_status == "healthy":
                overall_status = "degraded"

        # Check for assets missing in PostgreSQL
        if status.missing_in_postgres > 0:
            issues.append(f"{status.missing_in_postgres} assets in Neo4j not synced to PostgreSQL")
            recommendations.append(
                "Run sync from Neo4j: POST /api/sync/trigger with neo4j_to_pg direction"
            )

        # Check for orphaned assets in PostgreSQL
        if status.missing_in_neo4j > 50:
            issues.append(
                f"{status.missing_in_neo4j} assets in PostgreSQL not in Neo4j (may be stale)"
            )
            recommendations.append(
                "Consider running sync with mark_stale=true to deactivate stale assets"
            )

        # Estimate sync lag (rough estimate based on mismatch)
        sync_lag = min(status.count_mismatch * 5, 1440)  # Cap at 24 hours

        neo4j_status = "connected" if status.neo4j_connected else "disconnected"
        postgres_status = "connected" if status.postgres_connected else "disconnected"

        return SyncHealthResponse(
            status=overall_status,
            neo4j_status=neo4j_status,
            postgres_status=postgres_status,
            sync_lag=sync_lag,
            issues=issues,
            recommendations=recommendations,
        )

    except Exception as e:
        logger.error(f"Error getting sync health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get sync health: {str(e)}")


@router.post("/trigger", response_model=SyncResultResponse)
async def trigger_sync(request: SyncRequest, db: Session = Depends(get_db)):
    """
    Trigger a synchronization operation.

    Supports three sync directions:
    - neo4j_to_pg: Pull assets from Neo4j into PostgreSQL
    - pg_to_neo4j: Propagate finding counts to Neo4j nodes
    - bidirectional: Perform both operations

    The mark_stale option will deactivate PostgreSQL assets that no longer exist in Neo4j.
    """
    try:
        sync_service = get_neo4j_sync_service()

        if request.direction == SyncDirectionEnum.neo4j_to_pg:
            result = sync_service.sync_from_neo4j(db)
        elif request.direction == SyncDirectionEnum.pg_to_neo4j:
            result = sync_service.propagate_findings_to_neo4j(db)
        else:  # bidirectional
            result = sync_service.full_sync(db)

        # Optionally mark stale assets
        if request.mark_stale:
            stale_count = sync_service.mark_stale_assets(db)
            result.assets_deleted = stale_count

        return SyncResultResponse(
            success=result.success,
            direction=result.direction.value,
            assets_synced=result.assets_synced,
            assets_created=result.assets_created,
            assets_updated=result.assets_updated,
            assets_deleted=result.assets_deleted,
            findings_propagated=result.findings_propagated,
            errors=result.errors,
            warnings=result.warnings,
            duration_ms=result.duration_ms,
            timestamp=result.timestamp,
        )

    except Exception as e:
        logger.error(f"Sync failed: {e}")
        raise HTTPException(status_code=500, detail=f"Sync failed: {str(e)}")


@router.post("/trigger/background")
async def trigger_sync_background(
    request: SyncRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
):
    """
    Trigger a synchronization operation in the background.

    Returns immediately with a 202 Accepted status.
    Use GET /api/sync/status to check progress.
    """

    def run_sync():
        try:
            sync_service = get_neo4j_sync_service()
            if request.direction == SyncDirectionEnum.bidirectional:
                sync_service.full_sync(db)
            elif request.direction == SyncDirectionEnum.neo4j_to_pg:
                sync_service.sync_from_neo4j(db)
            else:
                sync_service.propagate_findings_to_neo4j(db)

            if request.mark_stale:
                sync_service.mark_stale_assets(db)

            logger.info("Background sync completed successfully")
        except Exception as e:
            logger.error(f"Background sync failed: {e}")

    background_tasks.add_task(run_sync)

    return {
        "status": "accepted",
        "message": "Sync operation started in background",
        "direction": request.direction.value,
        "check_status": "/api/sync/status",
    }


@router.get("/discrepancies", response_model=DiscrepancyResponse)
async def get_discrepancies(db: Session = Depends(get_db)):
    """
    Get detailed list of discrepancies between PostgreSQL and Neo4j.

    Returns:
    - Total count of discrepancies
    - Asset IDs missing in each database
    - Breakdown by asset type
    """
    try:
        sync_service = get_neo4j_sync_service()
        status = sync_service.get_sync_status(db)

        discrepancies = status.details.get("discrepancies", {})
        missing_in_pg = discrepancies.get("missing_in_pg", [])
        missing_in_neo4j = discrepancies.get("missing_in_neo4j", [])

        # Count by type (based on ID pattern for AWS resources)
        by_type: dict[str, int] = {}
        for asset_id in missing_in_pg + missing_in_neo4j:
            if ":ec2:" in asset_id:
                by_type["ec2"] = by_type.get("ec2", 0) + 1
            elif ":s3:" in asset_id or "s3:::" in asset_id:
                by_type["s3"] = by_type.get("s3", 0) + 1
            elif ":iam:" in asset_id:
                by_type["iam"] = by_type.get("iam", 0) + 1
            elif ":rds:" in asset_id:
                by_type["rds"] = by_type.get("rds", 0) + 1
            elif ":lambda:" in asset_id:
                by_type["lambda"] = by_type.get("lambda", 0) + 1
            else:
                by_type["other"] = by_type.get("other", 0) + 1

        return DiscrepancyResponse(
            total_discrepancies=len(missing_in_pg) + len(missing_in_neo4j),
            missing_in_postgres=missing_in_pg[:50],  # Limit response size
            missing_in_neo4j=missing_in_neo4j[:50],
            by_type=by_type,
        )

    except Exception as e:
        logger.error(f"Error getting discrepancies: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get discrepancies: {str(e)}")


@router.post("/propagate-findings", response_model=SyncResultResponse)
async def propagate_findings(db: Session = Depends(get_db)):
    """
    Propagate finding counts from PostgreSQL to Neo4j nodes.

    Updates Neo4j asset nodes with:
    - security_findings_count
    - critical_findings
    - high_findings
    - medium_findings
    - low_findings
    - last_security_scan timestamp

    This enables graph queries that consider security context.
    """
    try:
        sync_service = get_neo4j_sync_service()
        result = sync_service.propagate_findings_to_neo4j(db)

        return SyncResultResponse(
            success=result.success,
            direction=result.direction.value,
            assets_synced=result.assets_synced,
            assets_created=result.assets_created,
            assets_updated=result.assets_updated,
            assets_deleted=result.assets_deleted,
            findings_propagated=result.findings_propagated,
            errors=result.errors,
            warnings=result.warnings,
            duration_ms=result.duration_ms,
            timestamp=result.timestamp,
        )

    except Exception as e:
        logger.error(f"Finding propagation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to propagate findings: {str(e)}")
