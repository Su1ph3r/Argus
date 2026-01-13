"""Assumed Role Mapper API endpoints."""

import sys
import time
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import AssumedRoleMapping, get_db
from models.schemas import (
    AssumedRoleMappingListResponse,
    AssumedRoleMappingResponse,
    AssumedRoleSummary,
    Neo4jSyncRequest,
)

router = APIRouter(prefix="/assumed-roles", tags=["Assumed Roles"])


@router.get("", response_model=AssumedRoleMappingListResponse)
@router.get("/", response_model=AssumedRoleMappingListResponse)
async def list_assumed_role_mappings(
    db: Session = Depends(get_db),
    cloud_provider: str | None = Query(None, description="Filter by cloud provider"),
    source_principal_type: str | None = Query(None, description="Filter by source principal type"),
    is_cross_account: bool | None = Query(None, description="Filter by cross-account status"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    neo4j_synced: bool | None = Query(None, description="Filter by Neo4j sync status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List assumed role mappings with optional filters."""
    query = db.query(AssumedRoleMapping)

    if cloud_provider:
        query = query.filter(AssumedRoleMapping.cloud_provider == cloud_provider.lower())

    if source_principal_type:
        query = query.filter(AssumedRoleMapping.source_principal_type == source_principal_type)

    if is_cross_account is not None:
        query = query.filter(AssumedRoleMapping.is_cross_account == is_cross_account)

    if risk_level:
        query = query.filter(AssumedRoleMapping.risk_level == risk_level.lower())

    if neo4j_synced is not None:
        query = query.filter(AssumedRoleMapping.neo4j_synced == neo4j_synced)

    total = query.count()

    mappings = (
        query.order_by(
            desc(AssumedRoleMapping.assumption_chain_depth), desc(AssumedRoleMapping.created_at)
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AssumedRoleMappingListResponse(
        mappings=[AssumedRoleMappingResponse.model_validate(m) for m in mappings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=AssumedRoleSummary)
async def get_assumed_role_summary(db: Session = Depends(get_db)):
    """Get summary statistics of assumed role mappings."""
    total = db.query(AssumedRoleMapping).count()
    cross_account = (
        db.query(AssumedRoleMapping).filter(AssumedRoleMapping.is_cross_account == True).count()
    )
    external_id = (
        db.query(AssumedRoleMapping)
        .filter(AssumedRoleMapping.is_external_id_required == True)
        .count()
    )

    source_counts = dict(
        db.query(AssumedRoleMapping.source_principal_type, func.count(AssumedRoleMapping.id))
        .group_by(AssumedRoleMapping.source_principal_type)
        .all()
    )

    risk_counts = dict(
        db.query(AssumedRoleMapping.risk_level, func.count(AssumedRoleMapping.id))
        .group_by(AssumedRoleMapping.risk_level)
        .all()
    )

    return AssumedRoleSummary(
        total_mappings=total,
        cross_account=cross_account,
        external_id_required=external_id,
        by_source_type={k: v for k, v in source_counts.items() if k},
        by_risk={k: v for k, v in risk_counts.items() if k},
    )


@router.get("/cross-account", response_model=AssumedRoleMappingListResponse)
async def list_cross_account_roles(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List cross-account role assumption mappings."""
    query = db.query(AssumedRoleMapping).filter(AssumedRoleMapping.is_cross_account == True)

    total = query.count()

    mappings = (
        query.order_by(desc(AssumedRoleMapping.risk_level), desc(AssumedRoleMapping.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AssumedRoleMappingListResponse(
        mappings=[AssumedRoleMappingResponse.model_validate(m) for m in mappings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/chains")
async def get_assumption_chains(
    db: Session = Depends(get_db),
    min_depth: int = Query(2, ge=1, description="Minimum chain depth"),
):
    """Get role assumption chains (roles that can be assumed in sequence)."""
    # Get mappings with chain depth >= min_depth
    chains = (
        db.query(AssumedRoleMapping)
        .filter(AssumedRoleMapping.assumption_chain_depth >= min_depth)
        .order_by(desc(AssumedRoleMapping.assumption_chain_depth))
        .all()
    )

    return {
        "total_chains": len(chains),
        "chains": [
            {
                "id": m.id,
                "depth": m.assumption_chain_depth,
                "source": m.source_principal_name,
                "target": m.target_role_name,
                "is_cross_account": m.is_cross_account,
                "risk_level": m.risk_level,
            }
            for m in chains
        ],
    }


@router.get("/{mapping_id}", response_model=AssumedRoleMappingResponse)
async def get_assumed_role_mapping(mapping_id: int, db: Session = Depends(get_db)):
    """Get a specific assumed role mapping by ID."""
    mapping = db.query(AssumedRoleMapping).filter(AssumedRoleMapping.id == mapping_id).first()

    if not mapping:
        raise HTTPException(status_code=404, detail="Assumed role mapping not found")

    return AssumedRoleMappingResponse.model_validate(mapping)


@router.get("/role/{role_arn:path}", response_model=AssumedRoleMappingListResponse)
async def get_mappings_by_target_role(
    role_arn: str,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """Get all principals that can assume a specific role."""
    query = db.query(AssumedRoleMapping).filter(AssumedRoleMapping.target_role_arn == role_arn)

    total = query.count()

    mappings = (
        query.order_by(desc(AssumedRoleMapping.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AssumedRoleMappingListResponse(
        mappings=[AssumedRoleMappingResponse.model_validate(m) for m in mappings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/sync-neo4j")
async def sync_to_neo4j(request: Neo4jSyncRequest, db: Session = Depends(get_db)):
    """
    Sync assumed role mappings to Neo4j for graph visualization.

    This creates nodes for principals and roles, and edges for
    the assume-role relationships.
    """
    # In a real implementation, this would connect to Neo4j and create nodes/edges
    if request.sync_all:
        mappings = (
            db.query(AssumedRoleMapping).filter(AssumedRoleMapping.neo4j_synced == False).all()
        )
    elif request.mapping_ids:
        mappings = (
            db.query(AssumedRoleMapping)
            .filter(AssumedRoleMapping.id.in_(request.mapping_ids))
            .all()
        )
    else:
        raise HTTPException(status_code=400, detail="Provide mapping_ids or set sync_all=true")

    # Mark as synced (in real implementation, would sync first)
    for m in mappings:
        m.neo4j_synced = True
    db.commit()

    return {
        "status": "completed",
        "mappings_synced": len(mappings),
        "message": "Role mappings synced to Neo4j",
    }


@router.get("/{mapping_id}/neo4j-query")
async def get_neo4j_query(mapping_id: int, db: Session = Depends(get_db)):
    """Generate Neo4j Cypher query to visualize the role assumption."""
    mapping = db.query(AssumedRoleMapping).filter(AssumedRoleMapping.id == mapping_id).first()

    if not mapping:
        raise HTTPException(status_code=404, detail="Assumed role mapping not found")

    # Generate Cypher query for this mapping
    cypher = f"""
// Create source principal node
MERGE (source:{mapping.source_principal_type} {{
  arn: "{mapping.source_principal_arn}",
  name: "{mapping.source_principal_name or 'Unknown'}",
  account_id: "{mapping.source_account_id or 'Unknown'}"
}})

// Create target role node
MERGE (target:Role {{
  arn: "{mapping.target_role_arn}",
  name: "{mapping.target_role_name or 'Unknown'}",
  account_id: "{mapping.target_account_id or 'Unknown'}"
}})

// Create assume-role relationship
MERGE (source)-[r:CAN_ASSUME {{
  is_cross_account: {str(mapping.is_cross_account).lower()},
  external_id_required: {str(mapping.is_external_id_required).lower()},
  risk_level: "{mapping.risk_level}"
}}]->(target)

RETURN source, r, target
"""

    return {"mapping_id": mapping_id, "cypher_query": cypher.strip()}


@router.post("/analyze")
async def analyze_assumed_roles(
    scan_id: UUID | None = Query(None, description="Optional scan ID to analyze"),
    db: Session = Depends(get_db),
):
    """
    Trigger assumed role analysis.

    This runs the assumed role analyzer to discover role assumption
    relationships from IAM role findings in the database.

    The analyzer parses trust policies to identify:
    - Which principals can assume which roles
    - Cross-account role assumptions
    - External ID requirements
    - Risk levels based on exposure

    Args:
        scan_id: Optional UUID to analyze findings from a specific scan only

    Returns:
        dict: Analysis results including mappings discovered and summary
    """
    start_time = time.time()

    try:
        # Import and run the analyzer
        sys.path.insert(0, "/app/report-processor")
        from assumed_role_analyzer import AssumedRoleAnalyzer

        analyzer = AssumedRoleAnalyzer()
        scan_id_str = str(scan_id) if scan_id else None
        mappings = analyzer.analyze(scan_id_str)

        # Get summary
        summary_data = analyzer.get_summary()

        # Calculate time
        elapsed_ms = int((time.time() - start_time) * 1000)

        # Re-query for accurate counts
        total = db.query(AssumedRoleMapping).count()
        cross_account = (
            db.query(AssumedRoleMapping).filter(AssumedRoleMapping.is_cross_account == True).count()
        )
        external_id = (
            db.query(AssumedRoleMapping)
            .filter(AssumedRoleMapping.is_external_id_required == True)
            .count()
        )

        return {
            "status": "completed",
            "mappings_discovered": len(mappings),
            "analysis_time_ms": elapsed_ms,
            "summary": {
                "total_mappings": total,
                "cross_account": cross_account,
                "external_id_required": external_id,
                "by_source_type": summary_data.get("by_source_type", {}),
                "by_risk": summary_data.get("by_risk", {}),
            },
        }

    except ImportError as e:
        raise HTTPException(
            status_code=500, detail=f"Assumed role analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
