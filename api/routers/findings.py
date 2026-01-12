"""
Findings API Endpoints.

This module provides endpoints for querying and managing security findings
discovered by scanning tools. Findings represent security issues, misconfigurations,
and vulnerabilities across cloud infrastructure.

Key Features:
- List findings with filtering by severity, status, provider, tool, etc.
- Get aggregated summary statistics
- Update finding status (open, closed, mitigated, accepted)
- Cross-tool deduplication via canonical_id

Endpoints:
    GET /findings - List findings with filters
    GET /findings/summary - Get summary statistics
    GET /findings/{finding_id} - Get finding details
    PATCH /findings/{finding_id} - Update finding status/tags
    GET /findings/by-resource/{resource_id} - Get findings for a resource
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import asc, case, desc, func
from sqlalchemy.orm import Session

from models.database import Finding, get_db
from models.schemas import (
    AffectedResource,
    FindingListResponse,
    FindingResponse,
    FindingSummary,
    FindingUpdate,
)

router: APIRouter = APIRouter(prefix="/findings", tags=["Findings"])


def _aggregate_finding_data(finding: Finding, db: Session) -> dict[str, Any]:
    """Aggregate tool_sources and affected_resources for a finding based on canonical_id."""
    if not finding.canonical_id:
        return {
            "tool_sources": [finding.tool] if finding.tool else [],
            "affected_resources": [
                {
                    "id": finding.resource_id,
                    "name": finding.resource_name,
                    "region": finding.region,
                    "type": finding.resource_type,
                }
            ]
            if finding.resource_id
            else [],
            "affected_count": 1,
        }

    # Get all findings with the same canonical_id
    related_findings = (
        db.query(Finding)
        .filter(Finding.canonical_id == finding.canonical_id, Finding.status.in_(["open", "fail"]))
        .all()
    )

    # Aggregate tool sources (unique)
    tool_sources = list(set(f.tool for f in related_findings if f.tool))

    # Aggregate affected resources (unique by resource_id)
    seen_resources = set()
    affected_resources = []
    for f in related_findings:
        if f.resource_id and f.resource_id not in seen_resources:
            seen_resources.add(f.resource_id)
            affected_resources.append(
                {
                    "id": f.resource_id,
                    "name": f.resource_name,
                    "region": f.region,
                    "type": f.resource_type,
                }
            )

    return {
        "tool_sources": tool_sources,
        "affected_resources": affected_resources,
        "affected_count": len(affected_resources),
    }


# Severity ordering: critical is highest priority (0), info is lowest (4)
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@router.get("", response_model=FindingListResponse)
@router.get("/", response_model=FindingListResponse)
async def list_findings(
    db: Session = Depends(get_db),
    search: str | None = Query(None, description="Search in title, description, resource_id"),
    severity: str | None = Query(None, description="Filter by severity (comma-separated)"),
    status: str | None = Query(
        None, description="Filter by status (comma-separated, default: open,fail)"
    ),
    cloud_provider: str | None = Query(None, description="Filter by cloud provider"),
    tool: str | None = Query(None, description="Filter by scanning tool"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    scan_id: UUID | None = Query(None, description="Filter by scan ID"),
    sort_by: str | None = Query(
        "risk_score", description="Sort field (risk_score, severity, scan_date, title)"
    ),
    sort_order: str | None = Query("desc", description="Sort order (asc, desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """
    List findings with optional filters and pagination.

    Returns security findings from all scans with comprehensive filtering options.
    By default, only active findings (status: open, fail) are returned.

    Args:
        search: Text search in finding titles
        severity: Comma-separated severity levels (critical, high, medium, low)
        status: Comma-separated statuses (open, closed, mitigated, accepted, fail)
        cloud_provider: Filter by cloud provider (aws, azure, gcp, kubernetes)
        tool: Filter by scanning tool (prowler, scoutsuite, kubescape, etc.)
        resource_type: Filter by resource type
        scan_id: Filter by specific scan UUID
        page: Page number (1-indexed)
        page_size: Items per page (1-500)

    Returns:
        FindingListResponse: Paginated list of findings

    Example Request:
        GET /api/findings?severity=critical,high&cloud_provider=aws&page=1

    Security Note:
        Search terms are escaped to prevent SQL wildcard injection.
    """
    query = db.query(Finding)

    # Apply search filter - search ONLY by title
    # Security: Escape SQL LIKE wildcards to prevent wildcard injection
    if search:
        escaped_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        search_term = f"%{escaped_search}%"
        query = query.filter(Finding.title.ilike(search_term, escape="\\"))

    # Apply filters
    if severity:
        severities = [s.strip().lower() for s in severity.split(",")]
        query = query.filter(Finding.severity.in_(severities))

    # Default to active findings (open + fail) if no status specified
    if status:
        statuses = [s.strip().lower() for s in status.split(",")]
    else:
        statuses = ["open", "fail"]
    query = query.filter(Finding.status.in_(statuses))

    if cloud_provider:
        query = query.filter(Finding.cloud_provider == cloud_provider.lower())

    if tool:
        query = query.filter(Finding.tool == tool.lower())

    if resource_type:
        query = query.filter(Finding.resource_type == resource_type)

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)

    # Get total count
    total = query.count()

    # Build order_by clause based on sort parameters
    # Create severity case expression for proper ordering (critical=0 to info=4)
    severity_case = case(
        (Finding.severity == "critical", 0),
        (Finding.severity == "high", 1),
        (Finding.severity == "medium", 2),
        (Finding.severity == "low", 3),
        (Finding.severity == "info", 4),
        else_=5,
    )

    # Determine sort direction
    is_desc = sort_order.lower() == "desc" if sort_order else True

    # Build sort column based on sort_by parameter
    if sort_by == "risk_score":
        # Sort by risk_score, with NULL values last, then by severity
        if is_desc:
            order_clauses = [
                desc(Finding.risk_score).nulls_last(),
                severity_case.asc(),  # Secondary sort: critical first
                desc(Finding.scan_date),
            ]
        else:
            order_clauses = [
                asc(Finding.risk_score).nulls_last(),
                severity_case.desc(),  # Secondary sort: info first
                asc(Finding.scan_date),
            ]
    elif sort_by == "severity":
        # Sort by severity using proper criticality order
        if is_desc:
            order_clauses = [severity_case.asc(), desc(Finding.risk_score).nulls_last()]
        else:
            order_clauses = [severity_case.desc(), asc(Finding.risk_score).nulls_last()]
    elif sort_by == "scan_date":
        if is_desc:
            order_clauses = [desc(Finding.scan_date), severity_case.asc()]
        else:
            order_clauses = [asc(Finding.scan_date), severity_case.asc()]
    elif sort_by == "title":
        if is_desc:
            order_clauses = [desc(Finding.title), severity_case.asc()]
        else:
            order_clauses = [asc(Finding.title), severity_case.asc()]
    else:
        # Default: risk_score DESC, then severity by criticality
        order_clauses = [
            desc(Finding.risk_score).nulls_last(),
            severity_case.asc(),
            desc(Finding.scan_date),
        ]

    # Apply pagination and ordering
    findings = query.order_by(*order_clauses).offset((page - 1) * page_size).limit(page_size).all()

    return FindingListResponse(
        findings=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=FindingSummary)
async def get_findings_summary(
    db: Session = Depends(get_db),
    status: str | None = Query(
        None, description="Filter by status (comma-separated, default: open,fail)"
    ),
):
    """
    Get summary statistics of findings.

    Returns aggregated counts grouped by severity, cloud provider, and tool.
    Useful for dashboards and overview screens.

    Args:
        status: Comma-separated statuses to include (default: open,fail)

    Returns:
        FindingSummary: Aggregated finding statistics
            - total: Total finding count
            - critical/high/medium/low/info: Counts by severity
            - by_provider: Counts by cloud provider
            - by_tool: Counts by scanning tool
    """
    # Default to showing open and fail (active) findings
    if status:
        statuses = [s.strip().lower() for s in status.split(",")]
    else:
        statuses = ["open", "fail"]  # Both open and fail are considered active findings

    # Build base query
    base_query = db.query(Finding).filter(Finding.status.in_(statuses))

    # Get severity counts
    severity_counts = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.status.in_(statuses))
        .group_by(Finding.severity)
        .all()
    )

    # Get provider counts
    provider_counts = dict(
        db.query(Finding.cloud_provider, func.count(Finding.id))
        .filter(Finding.status.in_(statuses))
        .group_by(Finding.cloud_provider)
        .all()
    )

    # Get tool counts
    tool_counts = dict(
        db.query(Finding.tool, func.count(Finding.id))
        .filter(Finding.status.in_(statuses))
        .group_by(Finding.tool)
        .all()
    )

    total = base_query.count()

    return FindingSummary(
        total=total,
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        info=severity_counts.get("info", 0),
        by_provider={k: v for k, v in provider_counts.items() if k},
        by_tool={k: v for k, v in tool_counts.items() if k},
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """
    Get a specific finding by ID with aggregated data.

    Returns complete finding details including:
    - All fields from the finding record
    - Aggregated tool_sources (all tools that detected this issue)
    - Aggregated affected_resources (all resources with this issue)

    Args:
        finding_id: Database ID of the finding

    Returns:
        FindingResponse: Complete finding details

    Raises:
        HTTPException 404: If finding is not found
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get the base response
    response = FindingResponse.model_validate(finding)

    # Aggregate related findings data
    aggregated = _aggregate_finding_data(finding, db)
    response.tool_sources = aggregated["tool_sources"]
    response.affected_resources = [AffectedResource(**r) for r in aggregated["affected_resources"]]
    response.affected_count = aggregated["affected_count"]

    return response


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(finding_id: int, update: FindingUpdate, db: Session = Depends(get_db)):
    """
    Update a finding's status or tags.

    Allows updating the finding status (e.g., marking as mitigated or accepted)
    and adding custom tags for categorization.

    Args:
        finding_id: Database ID of the finding
        update: Fields to update:
            - status: New status (open, closed, mitigated, accepted, false_positive)
            - tags: Dictionary of custom tags to merge

    Returns:
        FindingResponse: Updated finding

    Raises:
        HTTPException 404: If finding is not found
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if update.status:
        finding.status = update.status.value

    if update.tags is not None:
        # Merge tags
        existing_tags = finding.tags or {}
        existing_tags.update(update.tags)
        finding.tags = existing_tags

    db.commit()
    db.refresh(finding)

    return FindingResponse.model_validate(finding)


@router.get("/by-resource/{resource_id}", response_model=list[FindingResponse])
async def get_findings_by_resource(resource_id: str, db: Session = Depends(get_db)):
    """
    Get all findings for a specific resource.

    Returns all security findings associated with a specific resource ID.
    Useful for resource-centric security views.

    Args:
        resource_id: The cloud resource identifier (e.g., ARN, resource name)

    Returns:
        List[FindingResponse]: All findings for the specified resource
    """
    findings = db.query(Finding).filter(Finding.resource_id == resource_id).all()

    return [FindingResponse.model_validate(f) for f in findings]
