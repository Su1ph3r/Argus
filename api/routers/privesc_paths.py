"""Privilege Escalation Paths API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import PrivescPath, get_db
from models.schemas import (
    PrivescPathEdge,
    PrivescPathListResponse,
    PrivescPathNode,
    PrivescPathResponse,
    PrivescPathSummary,
)

router = APIRouter(prefix="/privesc-paths", tags=["Privilege Escalation"])


def _convert_path_to_response(path: PrivescPath) -> PrivescPathResponse:
    """Convert database model to response schema."""
    nodes_data = path.path_nodes or []
    edges_data = path.path_edges or []
    mitre = path.mitre_techniques or []
    poc_cmds = path.poc_commands or []
    finding_ids = path.finding_ids or []

    nodes = [PrivescPathNode(**n) for n in nodes_data] if nodes_data else []
    edges = [PrivescPathEdge(**e) for e in edges_data] if edges_data else []

    return PrivescPathResponse(
        id=path.id,
        path_id=path.path_id,
        scan_id=path.scan_id,
        cloud_provider=path.cloud_provider,
        account_id=path.account_id,
        source_principal_type=path.source_principal_type,
        source_principal_arn=path.source_principal_arn,
        source_principal_name=path.source_principal_name,
        target_principal_type=path.target_principal_type,
        target_principal_arn=path.target_principal_arn,
        target_principal_name=path.target_principal_name,
        escalation_method=path.escalation_method,
        escalation_details=path.escalation_details,
        path_nodes=nodes,
        path_edges=edges,
        risk_score=path.risk_score,
        exploitability=path.exploitability,
        requires_conditions=path.requires_conditions,
        mitre_techniques=mitre,
        poc_commands=poc_cmds,
        finding_ids=finding_ids,
        status=path.status,
        created_at=path.created_at,
    )


@router.get("", response_model=PrivescPathListResponse)
@router.get("/", response_model=PrivescPathListResponse)
async def list_privesc_paths(
    db: Session = Depends(get_db),
    min_risk_score: int | None = Query(None, ge=0, le=100, description="Minimum risk score"),
    escalation_method: str | None = Query(None, description="Filter by escalation method"),
    cloud_provider: str | None = Query(None, description="Filter by cloud provider"),
    exploitability: str | None = Query(None, description="Filter by exploitability"),
    status: str | None = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
):
    """List privilege escalation paths with optional filters."""
    query = db.query(PrivescPath)

    if min_risk_score is not None:
        query = query.filter(PrivescPath.risk_score >= min_risk_score)

    if escalation_method:
        query = query.filter(PrivescPath.escalation_method == escalation_method)

    if cloud_provider:
        query = query.filter(PrivescPath.cloud_provider == cloud_provider.lower())

    if exploitability:
        query = query.filter(PrivescPath.exploitability == exploitability.lower())

    if status:
        query = query.filter(PrivescPath.status == status.lower())
    else:
        query = query.filter(PrivescPath.status == "open")

    total = query.count()

    paths = (
        query.order_by(desc(PrivescPath.risk_score), desc(PrivescPath.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PrivescPathListResponse(
        paths=[_convert_path_to_response(p) for p in paths],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=PrivescPathSummary)
async def get_privesc_summary(db: Session = Depends(get_db)):
    """Get summary statistics of privilege escalation paths."""
    total = db.query(PrivescPath).filter(PrivescPath.status == "open").count()
    critical = (
        db.query(PrivescPath)
        .filter(PrivescPath.status == "open", PrivescPath.risk_score >= 80)
        .count()
    )
    high = (
        db.query(PrivescPath)
        .filter(
            PrivescPath.status == "open", PrivescPath.risk_score >= 60, PrivescPath.risk_score < 80
        )
        .count()
    )

    method_counts = dict(
        db.query(PrivescPath.escalation_method, func.count(PrivescPath.id))
        .filter(PrivescPath.status == "open")
        .group_by(PrivescPath.escalation_method)
        .all()
    )

    target_counts = dict(
        db.query(PrivescPath.target_principal_type, func.count(PrivescPath.id))
        .filter(PrivescPath.status == "open")
        .group_by(PrivescPath.target_principal_type)
        .all()
    )

    return PrivescPathSummary(
        total_paths=total,
        critical_paths=critical,
        high_risk_paths=high,
        by_method={k: v for k, v in method_counts.items() if k},
        by_target={k: v for k, v in target_counts.items() if k},
    )


@router.get("/{path_id}", response_model=PrivescPathResponse)
async def get_privesc_path(path_id: int, db: Session = Depends(get_db)):
    """Get a specific privilege escalation path by ID."""
    path = db.query(PrivescPath).filter(PrivescPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Privilege escalation path not found")

    return _convert_path_to_response(path)


@router.get("/{path_id}/export")
async def export_privesc_path(
    path_id: int,
    format: str = Query("markdown", description="Export format: markdown, json"),
    db: Session = Depends(get_db),
):
    """Export a privilege escalation path for reporting."""
    path = db.query(PrivescPath).filter(PrivescPath.id == path_id).first()

    if not path:
        raise HTTPException(status_code=404, detail="Privilege escalation path not found")

    if format == "json":
        return _convert_path_to_response(path)

    # Markdown format
    md_lines = [
        f"# Privilege Escalation: {path.escalation_method}",
        "",
        f"**Risk Score:** {path.risk_score}/100",
        f"**Exploitability:** {path.exploitability}",
        f"**Cloud Provider:** {path.cloud_provider.upper()}",
        "",
        "## Source Principal",
        "",
        f"- **Type:** {path.source_principal_type}",
        f"- **Name:** {path.source_principal_name or 'N/A'}",
        f"- **ARN:** `{path.source_principal_arn or 'N/A'}`",
        "",
        "## Target Principal",
        "",
        f"- **Type:** {path.target_principal_type}",
        f"- **Name:** {path.target_principal_name or 'N/A'}",
        f"- **ARN:** `{path.target_principal_arn or 'N/A'}`",
        "",
        "## Escalation Details",
        "",
    ]

    if path.escalation_details:
        for key, value in path.escalation_details.items():
            md_lines.append(f"- **{key}:** {value}")

    md_lines.extend(
        [
            "",
            "## Proof of Concept Commands",
            "",
        ]
    )

    poc_commands = path.poc_commands or []
    if poc_commands:
        for cmd in poc_commands:
            md_lines.append(f"### {cmd.get('name', 'Command')}")
            md_lines.append("")
            md_lines.append("```bash")
            md_lines.append(cmd.get("command", "# No command"))
            md_lines.append("```")
            md_lines.append("")
    else:
        md_lines.append("No PoC commands available.")

    mitre = path.mitre_techniques or []
    if mitre:
        md_lines.extend(
            [
                "",
                "## MITRE ATT&CK Techniques",
                "",
            ]
        )
        for tech in mitre:
            md_lines.append(f"- {tech}")

    md_lines.extend(["", "---", "*Generated by Nubicustos Privilege Escalation Path Finder*"])

    return {"format": "markdown", "content": "\n".join(md_lines)}
