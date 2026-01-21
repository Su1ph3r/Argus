"""Blast Radius Calculator API endpoints.

This module provides API endpoints for calculating the potential impact
of compromised identities, including permission analysis, role assumption
chains, and cross-account scope.
"""

import sys
import time
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, Integer
from sqlalchemy.orm import Session

from models.database import EnumerateIamResult, AssumedRoleMapping, Finding, get_db

router = APIRouter(prefix="/blast-radius", tags=["Blast Radius"])


# ============================================================================
# API Endpoints
# ============================================================================


@router.post("/analyze")
async def analyze_blast_radius(
    scan_id: UUID | None = Query(None, description="Specific scan to analyze"),
    identity_arns: list[str] | None = Query(
        None, max_length=100, description="Specific identities to analyze"
    ),
    db: Session = Depends(get_db),
):
    """
    Trigger blast radius analysis for identities.

    Analyzes the potential impact of compromised identities by:
    - Querying direct permissions from enumerate_iam_results
    - Traversing role assumption chains from assumed_role_mappings
    - Calculating cross-account scope
    - Computing total blast radius scores

    Args:
        scan_id: Optional UUID to analyze identities from a specific scan
        identity_arns: Optional list of specific identity ARNs to analyze

    Returns:
        Analysis results with counts and summary by risk level
    """
    start_time = time.time()

    try:
        # Import the analyzer
        sys.path.insert(0, "/app/report-processor")
        from blast_radius_analyzer import BlastRadiusAnalyzer

        analyzer = BlastRadiusAnalyzer()

        # Determine which identities to analyze
        if identity_arns:
            # Analyze specific identities
            results = []
            for arn in identity_arns:
                analysis = analyzer.analyze_identity(
                    arn, str(scan_id) if scan_id else None
                )
                results.append(analysis)
        elif scan_id:
            # Analyze all identities in the scan
            results = analyzer.analyze_for_scan(str(scan_id))
        else:
            # Analyze all available identities (limited)
            query = db.query(EnumerateIamResult.principal_arn).distinct()
            query = query.filter(EnumerateIamResult.principal_arn.isnot(None))
            query = query.limit(100)  # Safety limit

            identities = [row[0] for row in query.all()]
            results = []
            for arn in identities:
                analysis = analyzer.analyze_identity(arn)
                results.append(analysis)

        # Get summary
        summary = analyzer.get_summary()
        elapsed_ms = int((time.time() - start_time) * 1000)

        return {
            "status": "completed",
            "analyses_created": len(results),
            "total_identities": len(results),
            "analysis_time_ms": elapsed_ms,
            "summary": {
                "by_risk_level": summary.get("by_risk_level", {}),
                "cross_account_identities": summary.get("cross_account_identities", 0),
                "avg_blast_radius": summary.get("avg_blast_radius", 0.0),
            },
        }

    except ImportError as e:
        raise HTTPException(
            status_code=500, detail=f"Blast radius analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/identity/{arn:path}")
async def get_identity_blast_radius(
    arn: str,
    scan_id: UUID | None = Query(None, description="Filter by scan ID"),
    db: Session = Depends(get_db),
):
    """
    Get blast radius analysis for a specific identity.

    Args:
        arn: The ARN of the identity to analyze
        scan_id: Optional scan ID to filter results

    Returns:
        Blast radius analysis for the identity, or not_found=True if not found
    """
    try:
        sys.path.insert(0, "/app/report-processor")
        from blast_radius_analyzer import BlastRadiusAnalyzer

        analyzer = BlastRadiusAnalyzer()

        # Check if identity exists in database
        query = db.query(EnumerateIamResult).filter(
            EnumerateIamResult.principal_arn == arn
        )
        if scan_id:
            query = query.filter(EnumerateIamResult.scan_id == scan_id)

        identity = query.first()

        if not identity:
            return {
                "identity_arn": arn,
                "analysis": None,
                "not_found": True,
            }

        # Perform analysis
        analysis = analyzer.analyze_identity(arn, str(scan_id) if scan_id else None)

        return {
            "identity_arn": arn,
            "analysis": analysis,
            "not_found": False,
        }

    except ImportError as e:
        raise HTTPException(
            status_code=500, detail=f"Blast radius analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/findings/{finding_id}")
async def get_finding_blast_radius(
    finding_id: int,
    db: Session = Depends(get_db),
):
    """
    Get blast radius context for a specific finding.

    Identifies related identities and their blast radius impact
    for a given security finding.

    Args:
        finding_id: The database ID of the finding

    Returns:
        Blast radius context including related identities and max risk
    """
    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        sys.path.insert(0, "/app/report-processor")
        from blast_radius_analyzer import BlastRadiusAnalyzer

        analyzer = BlastRadiusAnalyzer()

        # Find related identities based on resource_id or metadata
        related_identities = []

        # Check if the finding is about an IAM resource
        resource_id = finding.resource_id or ""
        if "arn:aws:iam" in resource_id:
            # Analyze this identity
            analysis = analyzer.analyze_identity(
                resource_id, str(finding.scan_id) if finding.scan_id else None
            )
            related_identities.append(analysis)

        # Also check for any identities mentioned in metadata
        metadata = finding.finding_metadata or {}
        if isinstance(metadata, dict):
            for key in ["principal_arn", "role_arn", "user_arn", "identity_arn"]:
                if key in metadata:
                    arn = metadata[key]
                    if arn and arn not in [a.get("identity_arn") for a in related_identities]:
                        analysis = analyzer.analyze_identity(
                            arn, str(finding.scan_id) if finding.scan_id else None
                        )
                        related_identities.append(analysis)

        # Calculate aggregated blast radius
        total_blast_radius = sum(
            a.get("total_blast_radius", 0) for a in related_identities
        )

        # Determine max risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        max_risk_level = "low"
        for analysis in related_identities:
            risk = analysis.get("risk_level", "low")
            if risk_order.get(risk, 4) < risk_order.get(max_risk_level, 4):
                max_risk_level = risk

        return {
            "finding_id": finding_id,
            "related_identities": related_identities,
            "total_blast_radius": total_blast_radius,
            "max_risk_level": max_risk_level,
        }

    except ImportError as e:
        raise HTTPException(
            status_code=500, detail=f"Blast radius analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/summary")
async def get_blast_radius_summary(
    scan_id: UUID | None = Query(None, description="Filter by scan ID"),
    db: Session = Depends(get_db),
):
    """
    Get summary of blast radius analyses.

    Provides aggregate statistics about identity blast radius
    across the environment.

    Args:
        scan_id: Optional scan ID to filter results

    Returns:
        Summary including totals, risk breakdown, and top risk identities
    """
    try:
        sys.path.insert(0, "/app/report-processor")
        from blast_radius_analyzer import BlastRadiusAnalyzer

        analyzer = BlastRadiusAnalyzer()

        # Query for identities
        query = db.query(EnumerateIamResult.principal_arn).distinct()
        query = query.filter(EnumerateIamResult.principal_arn.isnot(None))

        if scan_id:
            query = query.filter(EnumerateIamResult.scan_id == scan_id)

        # Limit for performance
        query = query.limit(500)
        identities = [row[0] for row in query.all()]

        # Get basic stats from database
        total_identities = len(identities)

        # Count capabilities (using case statements for boolean aggregation)
        caps_query = db.query(
            func.count(EnumerateIamResult.id).label("total"),
            func.sum(
                func.cast(EnumerateIamResult.admin_capable, Integer)
            ).label("admin"),
            func.sum(
                func.cast(EnumerateIamResult.privesc_capable, Integer)
            ).label("privesc"),
            func.sum(
                func.cast(EnumerateIamResult.data_access_capable, Integer)
            ).label("data_access"),
        )
        if scan_id:
            caps_query = caps_query.filter(EnumerateIamResult.scan_id == scan_id)

        caps_row = caps_query.first()

        # Count cross-account role mappings
        cross_account_query = db.query(func.count(AssumedRoleMapping.id)).filter(
            AssumedRoleMapping.is_cross_account == True
        )
        if scan_id:
            cross_account_query = cross_account_query.filter(
                AssumedRoleMapping.scan_id == scan_id
            )
        cross_account_count = cross_account_query.scalar() or 0

        # Count by identity type
        type_counts = {}
        for arn in identities[:100]:  # Sample for type breakdown
            if ":user/" in arn:
                type_counts["user"] = type_counts.get("user", 0) + 1
            elif ":role/" in arn:
                type_counts["role"] = type_counts.get("role", 0) + 1
            elif ":assumed-role/" in arn:
                type_counts["assumed-role"] = type_counts.get("assumed-role", 0) + 1
            else:
                type_counts["other"] = type_counts.get("other", 0) + 1

        # Get top risk identities (admin or privesc capable)
        top_risk_query = (
            db.query(EnumerateIamResult)
            .filter(
                (EnumerateIamResult.admin_capable == True)
                | (EnumerateIamResult.privesc_capable == True)
            )
            .filter(EnumerateIamResult.principal_arn.isnot(None))
        )
        if scan_id:
            top_risk_query = top_risk_query.filter(EnumerateIamResult.scan_id == scan_id)

        top_risk_query = top_risk_query.order_by(
            EnumerateIamResult.admin_capable.desc(),
            EnumerateIamResult.privesc_capable.desc(),
            EnumerateIamResult.permission_count.desc(),
        ).limit(10)

        top_risk_results = top_risk_query.all()

        # Analyze top risk identities
        top_risk_identities = []
        for result in top_risk_results:
            if result.principal_arn:
                try:
                    analysis = analyzer.analyze_identity(
                        result.principal_arn, str(scan_id) if scan_id else None
                    )
                    top_risk_identities.append(analysis)
                except Exception:
                    pass

        # Calculate risk level distribution (estimate based on capabilities)
        by_risk_level = {
            "critical": int(caps_row.admin or 0) if caps_row else 0,
            "high": int(caps_row.privesc or 0) if caps_row else 0,
            "medium": int(caps_row.data_access or 0) if caps_row else 0,
            "low": max(0, total_identities - (
                int(caps_row.admin or 0) +
                int(caps_row.privesc or 0) +
                int(caps_row.data_access or 0)
            )) if caps_row else total_identities,
        }

        # Calculate average blast radius from top identities
        avg_blast_radius = 0.0
        if top_risk_identities:
            total_radius = sum(a.get("total_blast_radius", 0) for a in top_risk_identities)
            avg_blast_radius = round(total_radius / len(top_risk_identities), 1)

        return {
            "total_identities": total_identities,
            "by_risk_level": by_risk_level,
            "by_identity_type": type_counts,
            "cross_account_identities": cross_account_count,
            "avg_blast_radius": avg_blast_radius,
            "top_risk_identities": top_risk_identities,
        }

    except ImportError as e:
        raise HTTPException(
            status_code=500, detail=f"Blast radius analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Summary generation failed: {str(e)}")


@router.get("/high-risk")
async def get_high_risk_identities(
    scan_id: UUID | None = Query(None, description="Filter by scan ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
):
    """
    List identities with high or critical blast radius.

    Returns identities that have admin capability, privesc capability,
    or significant cross-account access.

    Args:
        scan_id: Optional scan ID to filter results
        page: Page number for pagination
        page_size: Number of items per page

    Returns:
        Paginated list of high-risk identities with blast radius analysis
    """
    try:
        sys.path.insert(0, "/app/report-processor")
        from blast_radius_analyzer import BlastRadiusAnalyzer

        analyzer = BlastRadiusAnalyzer()

        # Query high-risk identities
        query = db.query(EnumerateIamResult).filter(
            (EnumerateIamResult.admin_capable == True)
            | (EnumerateIamResult.privesc_capable == True)
            | (EnumerateIamResult.data_access_capable == True)
        ).filter(EnumerateIamResult.principal_arn.isnot(None))

        if scan_id:
            query = query.filter(EnumerateIamResult.scan_id == scan_id)

        total = query.count()

        results = (
            query.order_by(
                EnumerateIamResult.admin_capable.desc(),
                EnumerateIamResult.privesc_capable.desc(),
                EnumerateIamResult.permission_count.desc(),
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        # Analyze each identity
        analyses = []
        for result in results:
            if result.principal_arn:
                try:
                    analysis = analyzer.analyze_identity(
                        result.principal_arn, str(scan_id) if scan_id else None
                    )
                    analyses.append(analysis)
                except Exception:
                    pass

        return {
            "identities": analyses,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    except ImportError as e:
        raise HTTPException(
            status_code=500, detail=f"Blast radius analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


@router.get("/cross-account")
async def get_cross_account_identities(
    scan_id: UUID | None = Query(None, description="Filter by scan ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
):
    """
    List identities with cross-account access.

    Returns identities that can assume roles in other AWS accounts,
    sorted by the number of cross-account roles.

    Args:
        scan_id: Optional scan ID to filter results
        page: Page number for pagination
        page_size: Number of items per page

    Returns:
        Paginated list of identities with cross-account access
    """
    try:
        sys.path.insert(0, "/app/report-processor")
        from blast_radius_analyzer import BlastRadiusAnalyzer

        analyzer = BlastRadiusAnalyzer()

        # Get identities with cross-account role mappings
        subquery = (
            db.query(
                AssumedRoleMapping.source_principal_arn,
                func.count(AssumedRoleMapping.id).label("cross_account_count"),
            )
            .filter(AssumedRoleMapping.is_cross_account == True)
            .filter(AssumedRoleMapping.source_principal_arn.isnot(None))
        )

        if scan_id:
            subquery = subquery.filter(AssumedRoleMapping.scan_id == scan_id)

        subquery = subquery.group_by(AssumedRoleMapping.source_principal_arn)
        subquery = subquery.subquery()

        # Join with enumerate_iam_results
        query = (
            db.query(EnumerateIamResult, subquery.c.cross_account_count)
            .join(
                subquery,
                EnumerateIamResult.principal_arn == subquery.c.source_principal_arn,
            )
            .order_by(subquery.c.cross_account_count.desc())
        )

        total = query.count()

        results = query.offset((page - 1) * page_size).limit(page_size).all()

        # Analyze each identity
        analyses = []
        for result, cross_account_count in results:
            if result.principal_arn:
                try:
                    analysis = analyzer.analyze_identity(
                        result.principal_arn, str(scan_id) if scan_id else None
                    )
                    analysis["cross_account_mapping_count"] = cross_account_count
                    analyses.append(analysis)
                except Exception:
                    pass

        return {
            "identities": analyses,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    except ImportError as e:
        raise HTTPException(
            status_code=500, detail=f"Blast radius analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


# ============================================================================
# Pydantic Schemas (for later integration into schemas.py)
# ============================================================================
#
# To integrate these schemas, add them to api/models/schemas.py:
#
# from enum import Enum
#
# class RiskLevel(str, Enum):
#     critical = "critical"
#     high = "high"
#     medium = "medium"
#     low = "low"
#
#
# class BlastRadiusAnalyzeRequest(BaseModel):
#     """Request to analyze blast radius."""
#     scan_id: UUID | None = Field(default=None, description="Specific scan to analyze")
#     identity_arns: list[str] | None = Field(
#         default=None, max_length=100, description="Specific identities to analyze"
#     )
#
#
# class PermissionBreakdown(BaseModel):
#     """Breakdown of permissions by service."""
#     service: str
#     action_count: int
#     resource_count: int
#     high_risk_actions: list[str] = []
#
#
# class ReachableRole(BaseModel):
#     """A role reachable through assumption chains."""
#     role_arn: str
#     role_name: str | None = None
#     account_id: str
#     is_cross_account: bool
#     assumption_depth: int
#
#
# class BlastRadiusAnalysis(BaseModel):
#     """Full blast radius analysis for an identity."""
#     analysis_id: str
#     identity_arn: str
#     identity_type: str
#     account_id: str
#     direct_permission_count: int = 0
#     direct_resource_count: int = 0
#     assumable_roles_count: int = 0
#     assumption_chain_depth: int = 1
#     cross_account_roles_count: int = 0
#     affected_accounts: list[str] = []
#     total_blast_radius: int = 0
#     risk_level: str = "medium"
#     reachable_resources: list[str] | None = None
#     reachable_roles: list[ReachableRole] | None = None
#     permission_breakdown: list[PermissionBreakdown] | None = None
#     created_at: datetime | None = None
#
#     class Config:
#         from_attributes = True
#
#
# class BlastRadiusAnalyzeResponse(BaseModel):
#     """Response from blast radius analysis."""
#     analyses_created: int
#     total_identities: int
#     summary: dict[str, int]  # risk_level -> count
#
#
# class BlastRadiusIdentityResponse(BaseModel):
#     """Response for identity blast radius query."""
#     identity_arn: str
#     analysis: BlastRadiusAnalysis | None = None
#     not_found: bool = False
#
#
# class BlastRadiusFindingResponse(BaseModel):
#     """Blast radius context for a finding."""
#     finding_id: int
#     related_identities: list[BlastRadiusAnalysis] = []
#     total_blast_radius: int = 0
#     max_risk_level: str = "low"
#
#
# class BlastRadiusSummaryResponse(BaseModel):
#     """Summary of blast radius analyses."""
#     total_identities: int = 0
#     by_risk_level: dict[str, int] = {}
#     by_identity_type: dict[str, int] = {}
#     cross_account_identities: int = 0
#     avg_blast_radius: float = 0.0
#     top_risk_identities: list[BlastRadiusAnalysis] = []
#
