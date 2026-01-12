"""Database management API endpoints."""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from models.database import (
    AssumedRoleMapping,
    AttackPath,
    CloudfoxResult,
    CredentialStatusCache,
    EnumerateIamResult,
    ExposedCredential,
    Finding,
    ImdsCheck,
    LambdaAnalysis,
    PacuResult,
    PrivescPath,
    PublicExposure,
    Scan,
    SeverityOverride,
    ToolExecution,
    get_db,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/database", tags=["Database"])


@router.delete("/purge")
async def purge_database(
    confirm: bool = Query(False, description="Confirm purge operation"),
    db: Session = Depends(get_db),
):
    """
    Purge all scan data from the database.

    This clears:
    - scans and findings
    - attack_paths
    - public_exposures
    - exposed_credentials
    - severity_overrides
    - privesc_paths
    - imds_checks
    - lambda_analysis
    - cloudfox_results
    - pacu_results
    - enumerate_iam_results
    - assumed_role_mappings
    - tool_executions

    Also resets credential_status_cache to 'unknown'.

    Requires confirm=true query parameter.
    """
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Add ?confirm=true to confirm database purge. This action cannot be undone.",
        )

    tables_purged = []
    rows_deleted = {}

    try:
        # Order matters due to foreign key constraints
        # Delete tables with foreign keys first

        # Severity overrides reference findings
        count = db.query(SeverityOverride).delete()
        rows_deleted["severity_overrides"] = count
        tables_purged.append("severity_overrides")

        # Findings reference scans
        count = db.query(Finding).delete()
        rows_deleted["findings"] = count
        tables_purged.append("findings")

        # Attack paths reference scans
        count = db.query(AttackPath).delete()
        rows_deleted["attack_paths"] = count
        tables_purged.append("attack_paths")

        # Public exposures reference scans
        count = db.query(PublicExposure).delete()
        rows_deleted["public_exposures"] = count
        tables_purged.append("public_exposures")

        # Exposed credentials reference scans
        count = db.query(ExposedCredential).delete()
        rows_deleted["exposed_credentials"] = count
        tables_purged.append("exposed_credentials")

        # Privesc paths reference scans
        count = db.query(PrivescPath).delete()
        rows_deleted["privesc_paths"] = count
        tables_purged.append("privesc_paths")

        # IMDS checks reference scans
        count = db.query(ImdsCheck).delete()
        rows_deleted["imds_checks"] = count
        tables_purged.append("imds_checks")

        # Lambda analysis reference scans
        count = db.query(LambdaAnalysis).delete()
        rows_deleted["lambda_analysis"] = count
        tables_purged.append("lambda_analysis")

        # CloudFox results reference scans
        count = db.query(CloudfoxResult).delete()
        rows_deleted["cloudfox_results"] = count
        tables_purged.append("cloudfox_results")

        # Pacu results reference scans
        count = db.query(PacuResult).delete()
        rows_deleted["pacu_results"] = count
        tables_purged.append("pacu_results")

        # Enumerate IAM results reference scans
        count = db.query(EnumerateIamResult).delete()
        rows_deleted["enumerate_iam_results"] = count
        tables_purged.append("enumerate_iam_results")

        # Assumed role mappings reference scans
        count = db.query(AssumedRoleMapping).delete()
        rows_deleted["assumed_role_mappings"] = count
        tables_purged.append("assumed_role_mappings")

        # Tool executions (no foreign keys to scans but related)
        count = db.query(ToolExecution).delete()
        rows_deleted["tool_executions"] = count
        tables_purged.append("tool_executions")

        # Now delete scans (parent table)
        count = db.query(Scan).delete()
        rows_deleted["scans"] = count
        tables_purged.append("scans")

        # Reset credential status cache to 'unknown'
        db.query(CredentialStatusCache).update(
            {
                "status": "unknown",
                "identity": None,
                "account_info": None,
                "tools_ready": [],
                "tools_partial": [],
                "tools_failed": [],
                "last_verified": None,
                "verification_error": None,
                "updated_at": datetime.utcnow(),
            }
        )
        tables_purged.append("credential_status_cache (reset)")

        db.commit()

        total_rows = sum(rows_deleted.values())
        logger.info(f"Database purged: {total_rows} rows deleted from {len(tables_purged)} tables")

        return {
            "success": True,
            "message": "Database purged successfully",
            "tables_purged": tables_purged,
            "rows_deleted": rows_deleted,
            "total_rows_deleted": total_rows,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to purge database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to purge database: {str(e)}")


@router.delete("/clear-old")
async def clear_old_scans(
    days: int = Query(90, ge=1, le=365, description="Delete scans older than this many days"),
    confirm: bool = Query(False, description="Confirm clear operation"),
    db: Session = Depends(get_db),
):
    """
    Clear scans and related data older than specified days.

    Requires confirm=true query parameter.
    """
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Add ?confirm=true to confirm clear operation. This action cannot be undone.",
        )

    from datetime import timedelta

    cutoff_date = datetime.utcnow() - timedelta(days=days)
    rows_deleted = {}

    try:
        # Get old scan IDs
        old_scan_ids = [
            s.scan_id for s in db.query(Scan).filter(Scan.started_at < cutoff_date).all()
        ]

        if not old_scan_ids:
            return {
                "success": True,
                "message": f"No scans older than {days} days found",
                "rows_deleted": {},
                "total_rows_deleted": 0,
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Delete related records first (FK constraints)
        count = (
            db.query(SeverityOverride)
            .filter(
                SeverityOverride.finding_id.in_(
                    db.query(Finding.id).filter(Finding.scan_id.in_(old_scan_ids))
                )
            )
            .delete(synchronize_session=False)
        )
        rows_deleted["severity_overrides"] = count

        count = (
            db.query(Finding)
            .filter(Finding.scan_id.in_(old_scan_ids))
            .delete(synchronize_session=False)
        )
        rows_deleted["findings"] = count

        count = (
            db.query(AttackPath)
            .filter(AttackPath.scan_id.in_(old_scan_ids))
            .delete(synchronize_session=False)
        )
        rows_deleted["attack_paths"] = count

        count = (
            db.query(PublicExposure)
            .filter(PublicExposure.scan_id.in_(old_scan_ids))
            .delete(synchronize_session=False)
        )
        rows_deleted["public_exposures"] = count

        count = (
            db.query(ExposedCredential)
            .filter(ExposedCredential.scan_id.in_(old_scan_ids))
            .delete(synchronize_session=False)
        )
        rows_deleted["exposed_credentials"] = count

        count = (
            db.query(PrivescPath)
            .filter(PrivescPath.scan_id.in_(old_scan_ids))
            .delete(synchronize_session=False)
        )
        rows_deleted["privesc_paths"] = count

        count = (
            db.query(ImdsCheck)
            .filter(ImdsCheck.scan_id.in_(old_scan_ids))
            .delete(synchronize_session=False)
        )
        rows_deleted["imds_checks"] = count

        count = (
            db.query(LambdaAnalysis)
            .filter(LambdaAnalysis.scan_id.in_(old_scan_ids))
            .delete(synchronize_session=False)
        )
        rows_deleted["lambda_analysis"] = count

        # Delete scans
        count = (
            db.query(Scan).filter(Scan.scan_id.in_(old_scan_ids)).delete(synchronize_session=False)
        )
        rows_deleted["scans"] = count

        db.commit()

        total_rows = sum(rows_deleted.values())
        logger.info(f"Cleared old scans: {total_rows} rows deleted (scans older than {days} days)")

        return {
            "success": True,
            "message": f"Cleared scans older than {days} days",
            "scans_deleted": len(old_scan_ids),
            "rows_deleted": rows_deleted,
            "total_rows_deleted": total_rows,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to clear old scans: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to clear old scans: {str(e)}")


@router.get("/stats")
async def get_database_stats(db: Session = Depends(get_db)):
    """Get current database statistics."""
    try:
        stats = {
            "scans": db.query(Scan).count(),
            "findings": db.query(Finding).count(),
            "attack_paths": db.query(AttackPath).count(),
            "public_exposures": db.query(PublicExposure).count(),
            "exposed_credentials": db.query(ExposedCredential).count(),
            "severity_overrides": db.query(SeverityOverride).count(),
            "privesc_paths": db.query(PrivescPath).count(),
            "imds_checks": db.query(ImdsCheck).count(),
            "lambda_analysis": db.query(LambdaAnalysis).count(),
            "tool_executions": db.query(ToolExecution).count(),
        }

        stats["total_records"] = sum(stats.values())

        return {"success": True, "stats": stats, "timestamp": datetime.utcnow().isoformat()}

    except Exception as e:
        logger.error(f"Failed to get database stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get database stats: {str(e)}")
