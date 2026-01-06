"""Export endpoints."""
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional, List
from datetime import datetime
import csv
import io
import json
from uuid import uuid4

from models.database import get_db, Finding
from models.schemas import ExportRequest, ExportResponse, SeverityLevel, FindingStatus

router = APIRouter(prefix="/exports", tags=["Exports"])


@router.get("/csv")
async def export_findings_csv(
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="Filter by severity (comma-separated)"),
    status: Optional[str] = Query("open", description="Filter by status"),
    cloud_provider: Optional[str] = Query(None, description="Filter by cloud provider"),
    include_remediation: bool = Query(True, description="Include remediation guidance")
):
    """Export findings as CSV file."""
    query = db.query(Finding)

    # Apply filters
    if severity:
        severities = [s.strip().lower() for s in severity.split(",")]
        query = query.filter(Finding.severity.in_(severities))

    if status:
        statuses = [s.strip().lower() for s in status.split(",")]
        query = query.filter(Finding.status.in_(statuses))

    if cloud_provider:
        query = query.filter(Finding.cloud_provider == cloud_provider.lower())

    findings = query.order_by(
        Finding.severity,
        desc(Finding.scan_date)
    ).all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    headers = [
        "finding_id", "tool", "cloud_provider", "severity", "status",
        "title", "resource_type", "resource_id", "resource_name",
        "region", "scan_date"
    ]
    if include_remediation:
        headers.append("remediation")

    writer.writerow(headers)

    # Data rows
    for f in findings:
        row = [
            f.finding_id, f.tool, f.cloud_provider, f.severity, f.status,
            f.title, f.resource_type, f.resource_id, f.resource_name,
            f.region, f.scan_date.isoformat() if f.scan_date else ""
        ]
        if include_remediation:
            row.append(f.remediation or "")
        writer.writerow(row)

    output.seek(0)

    filename = f"findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/json")
async def export_findings_json(
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="Filter by severity (comma-separated)"),
    status: Optional[str] = Query("open", description="Filter by status"),
    cloud_provider: Optional[str] = Query(None, description="Filter by cloud provider")
):
    """Export findings as JSON file."""
    query = db.query(Finding)

    # Apply filters
    if severity:
        severities = [s.strip().lower() for s in severity.split(",")]
        query = query.filter(Finding.severity.in_(severities))

    if status:
        statuses = [s.strip().lower() for s in status.split(",")]
        query = query.filter(Finding.status.in_(statuses))

    if cloud_provider:
        query = query.filter(Finding.cloud_provider == cloud_provider.lower())

    findings = query.order_by(
        Finding.severity,
        desc(Finding.scan_date)
    ).all()

    # Build JSON structure
    export_data = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "filters": {
            "severity": severity,
            "status": status,
            "cloud_provider": cloud_provider
        },
        "total_findings": len(findings),
        "findings": [
            {
                "finding_id": f.finding_id,
                "tool": f.tool,
                "cloud_provider": f.cloud_provider,
                "severity": f.severity,
                "status": f.status,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "resource_type": f.resource_type,
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "region": f.region,
                "risk_score": float(f.risk_score) if f.risk_score else None,
                "cvss_score": float(f.cvss_score) if f.cvss_score else None,
                "cve_id": f.cve_id,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
                "scan_date": f.scan_date.isoformat() if f.scan_date else None
            }
            for f in findings
        ]
    }

    filename = f"findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    return StreamingResponse(
        iter([json.dumps(export_data, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.post("/generate", response_model=ExportResponse)
async def generate_export(
    export_request: ExportRequest,
    db: Session = Depends(get_db)
):
    """Generate an export package with specified filters."""
    query = db.query(Finding)

    # Apply filters
    if export_request.severity_filter:
        severities = [s.value for s in export_request.severity_filter]
        query = query.filter(Finding.severity.in_(severities))

    if export_request.status_filter:
        statuses = [s.value for s in export_request.status_filter]
        query = query.filter(Finding.status.in_(statuses))

    if export_request.cloud_provider:
        query = query.filter(Finding.cloud_provider == export_request.cloud_provider.lower())

    count = query.count()

    export_id = str(uuid4())[:8]
    filename = f"findings_export_{export_id}.{export_request.format}"

    return ExportResponse(
        export_id=export_id,
        filename=filename,
        format=export_request.format,
        record_count=count,
        download_url=f"/api/exports/{export_request.format}",
        generated_at=datetime.utcnow()
    )


@router.get("/summary")
async def export_summary(
    db: Session = Depends(get_db)
):
    """Get export-ready summary of current findings."""
    from sqlalchemy import func

    # Severity breakdown
    severity_data = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.status == "open")
        .group_by(Finding.severity)
        .all()
    )

    # Provider breakdown
    provider_data = dict(
        db.query(Finding.cloud_provider, func.count(Finding.id))
        .filter(Finding.status == "open")
        .group_by(Finding.cloud_provider)
        .all()
    )

    # Tool breakdown
    tool_data = dict(
        db.query(Finding.tool, func.count(Finding.id))
        .filter(Finding.status == "open")
        .group_by(Finding.tool)
        .all()
    )

    total = db.query(Finding).filter(Finding.status == "open").count()

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_open_findings": total,
        "by_severity": severity_data,
        "by_provider": {k: v for k, v in provider_data.items() if k},
        "by_tool": {k: v for k, v in tool_data.items() if k}
    }
