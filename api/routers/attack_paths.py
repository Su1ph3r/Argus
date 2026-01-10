"""Attack paths API endpoints."""
import time
import subprocess
import sys
import os
from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import Optional, List
from uuid import UUID
from collections import defaultdict

from models.database import get_db, AttackPath, Finding
from models.schemas import (
    AttackPathResponse,
    AttackPathListResponse,
    AttackPathSummary,
    AttackPathAnalyzeRequest,
    AttackPathAnalyzeResponse,
    AttackPathNode,
    AttackPathEdge,
    PoCStep,
)

router = APIRouter(prefix="/attack-paths", tags=["Attack Paths"])


def _convert_path_to_response(path: AttackPath) -> AttackPathResponse:
    """Convert database model to response schema."""
    # Parse JSONB fields
    nodes_data = path.nodes or []
    edges_data = path.edges or []
    poc_steps_data = path.poc_steps or []
    finding_ids = path.finding_ids or []
    mitre_tactics = path.mitre_tactics or []
    aws_services = path.aws_services or []

    # Convert to Pydantic models
    nodes = [AttackPathNode(**n) for n in nodes_data]
    edges = [AttackPathEdge(**e) for e in edges_data]
    poc_steps = [PoCStep(**s) for s in poc_steps_data]

    return AttackPathResponse(
        id=path.id,
        path_id=path.path_id,
        scan_id=path.scan_id,
        name=path.name,
        description=path.description,
        entry_point_type=path.entry_point_type,
        entry_point_id=path.entry_point_id,
        entry_point_name=path.entry_point_name,
        target_type=path.target_type,
        target_description=path.target_description,
        nodes=nodes,
        edges=edges,
        finding_ids=finding_ids,
        risk_score=path.risk_score,
        exploitability=path.exploitability,
        impact=path.impact,
        hop_count=path.hop_count,
        requires_authentication=path.requires_authentication,
        requires_privileges=path.requires_privileges,
        poc_available=path.poc_available,
        poc_steps=poc_steps,
        mitre_tactics=mitre_tactics,
        aws_services=aws_services,
        created_at=path.created_at,
    )


@router.get("", response_model=AttackPathListResponse)
@router.get("/", response_model=AttackPathListResponse)
async def list_attack_paths(
    db: Session = Depends(get_db),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score (inclusive)"),
    max_risk_score: Optional[int] = Query(None, ge=0, le=100, description="Maximum risk score (exclusive)"),
    exploitability: Optional[str] = Query(None, description="Filter by exploitability: confirmed, likely, theoretical"),
    entry_point_type: Optional[str] = Query(None, description="Filter by entry point type"),
    target_type: Optional[str] = Query(None, description="Filter by target type"),
    scan_id: Optional[UUID] = Query(None, description="Filter by scan ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page")
):
    """List attack paths with optional filters."""
    query = db.query(AttackPath)

    # Apply filters
    if min_risk_score is not None:
        query = query.filter(AttackPath.risk_score >= min_risk_score)

    if max_risk_score is not None:
        query = query.filter(AttackPath.risk_score < max_risk_score)

    if exploitability:
        query = query.filter(AttackPath.exploitability == exploitability.lower())

    if entry_point_type:
        query = query.filter(AttackPath.entry_point_type == entry_point_type)

    if target_type:
        query = query.filter(AttackPath.target_type == target_type)

    if scan_id:
        query = query.filter(AttackPath.scan_id == scan_id)

    # Get total count
    total = query.count()

    # Apply pagination and ordering (highest risk first)
    paths = query.order_by(
        desc(AttackPath.risk_score),
        desc(AttackPath.created_at)
    ).offset((page - 1) * page_size).limit(page_size).all()

    return AttackPathListResponse(
        paths=[_convert_path_to_response(p) for p in paths],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/summary", response_model=AttackPathSummary)
async def get_attack_paths_summary(db: Session = Depends(get_db)):
    """Get summary statistics for attack paths."""
    # Count by risk level
    total = db.query(AttackPath).count()
    critical = db.query(AttackPath).filter(AttackPath.risk_score >= 80).count()
    high = db.query(AttackPath).filter(AttackPath.risk_score >= 60, AttackPath.risk_score < 80).count()
    medium = db.query(AttackPath).filter(AttackPath.risk_score >= 40, AttackPath.risk_score < 60).count()
    low = db.query(AttackPath).filter(AttackPath.risk_score < 40).count()

    # Count by entry point type
    entry_counts = dict(
        db.query(AttackPath.entry_point_type, func.count(AttackPath.id))
        .group_by(AttackPath.entry_point_type)
        .all()
    )

    # Count by target type
    target_counts = dict(
        db.query(AttackPath.target_type, func.count(AttackPath.id))
        .group_by(AttackPath.target_type)
        .all()
    )

    # Calculate average risk score
    avg_score_result = db.query(func.avg(AttackPath.risk_score)).scalar()
    avg_score = float(avg_score_result) if avg_score_result else 0.0

    # Get top MITRE tactics (need to unnest JSONB array)
    all_paths = db.query(AttackPath.mitre_tactics).all()
    tactic_counts = defaultdict(int)
    for (tactics,) in all_paths:
        if tactics:
            for tactic in tactics:
                tactic_counts[tactic] += 1

    # Sort by count and get top 5
    top_tactics = sorted(tactic_counts.keys(), key=lambda t: tactic_counts[t], reverse=True)[:5]

    return AttackPathSummary(
        total_paths=total,
        critical_paths=critical,
        high_risk_paths=high,
        medium_risk_paths=medium,
        low_risk_paths=low,
        entry_point_types=entry_counts,
        target_types=target_counts,
        top_mitre_tactics=top_tactics,
        avg_risk_score=round(avg_score, 1)
    )


@router.get("/{path_id}", response_model=AttackPathResponse)
async def get_attack_path(
    path_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific attack path by ID."""
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    return _convert_path_to_response(path)


@router.get("/by-path-id/{path_id}", response_model=AttackPathResponse)
async def get_attack_path_by_path_id(
    path_id: str,
    db: Session = Depends(get_db)
):
    """Get a specific attack path by its path_id hash."""
    path = db.query(AttackPath).filter(AttackPath.path_id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    return _convert_path_to_response(path)


@router.post("/analyze", response_model=AttackPathAnalyzeResponse)
async def analyze_attack_paths(
    request: AttackPathAnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Trigger attack path analysis.

    This runs the attack path analyzer to discover new paths
    from the current findings in the database.
    """
    start_time = time.time()

    try:
        # Import and run the analyzer
        # Note: In production, this might be better as a background task
        sys.path.insert(0, '/app/report-processor')
        from attack_path_analyzer import AttackPathAnalyzer

        analyzer = AttackPathAnalyzer()
        scan_id_str = str(request.scan_id) if request.scan_id else None
        paths = analyzer.analyze(scan_id_str)

        # Get summary
        summary_data = analyzer.get_summary()

        # Calculate time
        elapsed_ms = int((time.time() - start_time) * 1000)

        # Build summary response
        # Re-query for accurate counts
        total = db.query(AttackPath).count()
        critical = db.query(AttackPath).filter(AttackPath.risk_score >= 80).count()
        high = db.query(AttackPath).filter(AttackPath.risk_score >= 60, AttackPath.risk_score < 80).count()
        medium = db.query(AttackPath).filter(AttackPath.risk_score >= 40, AttackPath.risk_score < 60).count()
        low = db.query(AttackPath).filter(AttackPath.risk_score < 40).count()

        summary = AttackPathSummary(
            total_paths=total,
            critical_paths=critical,
            high_risk_paths=high,
            medium_risk_paths=medium,
            low_risk_paths=low,
            entry_point_types={},
            target_types={},
            top_mitre_tactics=[],
            avg_risk_score=0.0
        )

        return AttackPathAnalyzeResponse(
            paths_discovered=len(paths),
            analysis_time_ms=elapsed_ms,
            summary=summary
        )

    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Attack path analyzer not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get("/{path_id}/findings", response_model=List[dict])
async def get_path_findings(
    path_id: int,
    db: Session = Depends(get_db)
):
    """Get all findings associated with an attack path."""
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    finding_ids = path.finding_ids or []
    if not finding_ids:
        return []

    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()

    return [
        {
            'id': f.id,
            'finding_id': f.finding_id,
            'title': f.title,
            'severity': f.severity,
            'resource_type': f.resource_type,
            'resource_id': f.resource_id,
            'region': f.region,
        }
        for f in findings
    ]


@router.delete("/{path_id}")
async def delete_attack_path(
    path_id: int,
    db: Session = Depends(get_db)
):
    """Delete an attack path."""
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    db.delete(path)
    db.commit()

    return {"message": "Attack path deleted", "path_id": path_id}


@router.get("/{path_id}/export")
async def export_attack_path(
    path_id: int,
    format: str = Query("markdown", description="Export format: markdown, json"),
    db: Session = Depends(get_db)
):
    """Export an attack path in various formats for reporting."""
    path = db.query(AttackPath).filter(AttackPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    if format == "json":
        return _convert_path_to_response(path)

    # Markdown format for pentest reports
    md_lines = [
        f"# Attack Path: {path.name}",
        "",
        f"**Risk Score:** {path.risk_score}/100",
        f"**Exploitability:** {path.exploitability}",
        f"**Impact:** {path.impact}",
        f"**Hops:** {path.hop_count}",
        "",
        "## Overview",
        "",
        path.description or "No description available.",
        "",
        "## Entry Point",
        "",
        f"- **Type:** {path.entry_point_type}",
        f"- **Resource:** {path.entry_point_name or 'N/A'}",
        f"- **ID:** `{path.entry_point_id or 'N/A'}`",
        "",
        "## Target",
        "",
        f"- **Type:** {path.target_type}",
        f"- **Description:** {path.target_description or 'N/A'}",
        "",
        "## Attack Path Steps",
        "",
    ]

    # Add nodes
    nodes = path.nodes or []
    for i, node in enumerate(nodes):
        md_lines.append(f"{i + 1}. **{node.get('name', 'Unknown')}** ({node.get('type', 'unknown')})")
        if node.get('resource_id'):
            md_lines.append(f"   - Resource: `{node.get('resource_id')}`")
        if node.get('region'):
            md_lines.append(f"   - Region: {node.get('region')}")

    md_lines.extend([
        "",
        "## Proof of Concept",
        "",
    ])

    # Add PoC steps
    poc_steps = path.poc_steps or []
    if poc_steps:
        for step in poc_steps:
            md_lines.append(f"### Step {step.get('step', '?')}: {step.get('name', 'Unknown')}")
            md_lines.append("")
            md_lines.append(step.get('description', ''))
            md_lines.append("")
            md_lines.append("```bash")
            md_lines.append(step.get('command', '# No command available'))
            md_lines.append("```")
            md_lines.append("")
            if step.get('mitre_technique'):
                md_lines.append(f"*MITRE ATT&CK: {step.get('mitre_technique')}*")
            md_lines.append("")
    else:
        md_lines.append("No PoC steps available for this path.")

    md_lines.extend([
        "",
        "## MITRE ATT&CK Mapping",
        "",
    ])

    mitre_tactics = path.mitre_tactics or []
    if mitre_tactics:
        for tactic in mitre_tactics:
            md_lines.append(f"- {tactic}")
    else:
        md_lines.append("No MITRE ATT&CK tactics mapped.")

    md_lines.extend([
        "",
        "## Affected AWS Services",
        "",
    ])

    aws_services = path.aws_services or []
    if aws_services:
        for service in aws_services:
            md_lines.append(f"- {service}")
    else:
        md_lines.append("No specific AWS services identified.")

    md_lines.extend([
        "",
        "---",
        f"*Generated by Nubicustos Attack Path Analyzer*",
    ])

    return {"format": "markdown", "content": "\n".join(md_lines)}
