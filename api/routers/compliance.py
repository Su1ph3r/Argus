"""
Compliance API Endpoints.

This module provides endpoints for querying compliance framework data
including pass/fail status for controls across different frameworks
(CIS, PCI-DSS, SOC2, HIPAA, NIST, GDPR, etc.).

Key Features:
- List all compliance frameworks with summary statistics
- Get detailed control-level data for a specific framework
- Export compliance data as CSV

Endpoints:
    GET /compliance/frameworks - List all frameworks with pass/fail percentages
    GET /compliance/frameworks/{framework} - Get control details for a framework
    GET /compliance/summary - Get high-level compliance summary
    GET /compliance/export/csv - Export compliance data as CSV
"""

import logging
import re
from io import StringIO

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from models.database import get_db
from models.schemas import (
    ComplianceControl,
    ComplianceFrameworkDetail,
    ComplianceFrameworksResponse,
    ComplianceFrameworkSummary,
    ComplianceSummaryResponse,
)

router: APIRouter = APIRouter(prefix="/compliance", tags=["Compliance"])
logger = logging.getLogger(__name__)


def _get_framework_summaries(db: Session) -> list[ComplianceFrameworkSummary]:
    """Get summary statistics for all compliance frameworks from findings JSONB."""
    # Query extracts framework names and control counts from compliance_frameworks JSONB
    # Structure: {"Framework": ["control1", "control2", ...]}
    query = text("""
        WITH framework_data AS (
            SELECT
                f.id as finding_id,
                f.status,
                framework_key as framework,
                jsonb_array_length(f.compliance_frameworks->framework_key) as control_count
            FROM findings f,
            LATERAL jsonb_object_keys(f.compliance_frameworks) as framework_key
            WHERE f.compliance_frameworks IS NOT NULL
              AND jsonb_typeof(f.compliance_frameworks) = 'object'
        )
        SELECT
            framework,
            SUM(control_count) as controls_checked,
            SUM(CASE WHEN status NOT IN ('open', 'fail') THEN control_count ELSE 0 END)
                as controls_passed,
            COUNT(DISTINCT CASE WHEN status IN ('open', 'fail') THEN finding_id END)
                as open_findings
        FROM framework_data
        GROUP BY framework
        ORDER BY framework
    """)

    result = db.execute(query)
    rows = result.fetchall()

    frameworks = []
    for row in rows:
        framework = row[0]
        controls_checked = int(row[1] or 0)
        controls_passed = int(row[2] or 0)
        controls_failed = controls_checked - controls_passed
        open_findings = int(row[3] or 0)
        if controls_checked > 0:
            pass_percentage = round((controls_passed / controls_checked * 100), 1)
        else:
            pass_percentage = 0.0

        frameworks.append(
            ComplianceFrameworkSummary(
                framework=framework,
                controls_checked=controls_checked,
                controls_passed=controls_passed,
                controls_failed=controls_failed,
                pass_percentage=pass_percentage,
                open_findings=open_findings,
            )
        )

    return frameworks


@router.get("/frameworks", response_model=ComplianceFrameworksResponse)
async def list_frameworks(db: Session = Depends(get_db)):
    """
    List all compliance frameworks with summary statistics.

    Returns pass/fail percentages and control counts for each framework
    found in the findings compliance_frameworks JSONB column.

    Returns:
        ComplianceFrameworksResponse: List of frameworks with statistics
    """
    frameworks = _get_framework_summaries(db)
    return ComplianceFrameworksResponse(frameworks=frameworks, total=len(frameworks))


@router.get("/summary", response_model=ComplianceSummaryResponse)
async def get_compliance_summary(db: Session = Depends(get_db)):
    """
    Get high-level compliance summary across all frameworks.

    Returns overall pass/fail statistics aggregated across all frameworks.

    Returns:
        ComplianceSummaryResponse: Aggregated compliance statistics
    """
    frameworks = _get_framework_summaries(db)

    total_controls = sum(f.controls_checked for f in frameworks)
    total_passed = sum(f.controls_passed for f in frameworks)
    total_failed = sum(f.controls_failed for f in frameworks)
    if total_controls > 0:
        overall_pass_percentage = round((total_passed / total_controls * 100), 1)
    else:
        overall_pass_percentage = 0.0

    return ComplianceSummaryResponse(
        frameworks_count=len(frameworks),
        total_controls=total_controls,
        total_passed=total_passed,
        total_failed=total_failed,
        overall_pass_percentage=overall_pass_percentage,
        by_framework=frameworks,
    )


@router.get("/frameworks/{framework}", response_model=ComplianceFrameworkDetail)
async def get_framework_details(
    framework: str = Path(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9\-_\s\.]+$",
        description="Framework name (e.g., CIS, PCI-DSS, SOC2)",
    ),
    db: Session = Depends(get_db),
):
    """
    Get detailed control-level data for a specific compliance framework.

    Args:
        framework: The framework name (e.g., "CIS", "PCI-DSS", "SOC2")

    Returns:
        ComplianceFrameworkDetail: Framework details with all controls

    Raises:
        HTTPException: 404 if framework not found
    """
    # Get control details for the framework from JSONB
    # Extracts individual control IDs from the array for the given framework
    query = text("""
        WITH control_data AS (
            SELECT
                f.id as finding_id,
                f.title as finding_title,
                f.status,
                f.severity,
                control_id
            FROM findings f,
            LATERAL jsonb_array_elements_text(f.compliance_frameworks->:framework)
                AS control_id
            WHERE f.compliance_frameworks ? :framework
        )
        SELECT
            control_id,
            MAX(finding_title) as control_title,
            NULL as control_description,
            NULL as requirement,
            MAX(severity) as severity,
            CASE
                WHEN COUNT(CASE WHEN status IN ('open', 'fail') THEN 1 END) > 0
                THEN 'fail'
                ELSE 'pass'
            END as status,
            COUNT(CASE WHEN status IN ('open', 'fail') THEN 1 END) as finding_count
        FROM control_data
        GROUP BY control_id
        ORDER BY control_id
    """)

    result = db.execute(query, {"framework": framework})
    rows = result.fetchall()

    if not rows:
        raise HTTPException(
            status_code=404, detail=f"Framework '{framework}' not found"
        )

    controls = []
    passed_count = 0
    for row in rows:
        status = row[5]
        if status == "pass":
            passed_count += 1
        controls.append(
            ComplianceControl(
                control_id=row[0],
                control_title=row[1],
                control_description=row[2],
                requirement=row[3],
                severity=row[4],
                status=status,
                finding_count=row[6] or 0,
            )
        )

    total_controls = len(controls)
    failed_count = total_controls - passed_count
    if total_controls > 0:
        pass_percentage = round((passed_count / total_controls * 100), 1)
    else:
        pass_percentage = 0.0

    # Calculate open findings for this framework
    open_findings_query = text("""
        SELECT COUNT(DISTINCT f.id)
        FROM findings f
        WHERE f.compliance_frameworks ? :framework
          AND f.status IN ('open', 'fail')
    """)
    open_findings_result = db.execute(open_findings_query, {"framework": framework})
    open_findings = open_findings_result.scalar() or 0

    summary = ComplianceFrameworkSummary(
        framework=framework,
        controls_checked=total_controls,
        controls_passed=passed_count,
        controls_failed=failed_count,
        pass_percentage=pass_percentage,
        open_findings=open_findings,
    )

    return ComplianceFrameworkDetail(
        framework=framework,
        controls=controls,
        summary=summary,
    )


@router.get("/export/csv")
async def export_compliance_csv(
    framework: str | None = Query(None, description="Filter by framework"),
    db: Session = Depends(get_db),
):
    """
    Export compliance data as CSV.

    Args:
        framework: Optional framework filter

    Returns:
        StreamingResponse: CSV file download
    """
    # Build query based on filter
    if framework:
        query = text("""
            WITH control_data AS (
                SELECT
                    :framework as framework,
                    control_id,
                    f.title as finding_title,
                    f.status,
                    f.severity
                FROM findings f,
                LATERAL jsonb_array_elements_text(f.compliance_frameworks->:framework)
                    AS control_id
                WHERE f.compliance_frameworks ? :framework
            )
            SELECT
                framework,
                control_id,
                MAX(finding_title) as control_title,
                NULL as requirement,
                MAX(severity) as severity,
                CASE
                    WHEN COUNT(CASE WHEN status IN ('open', 'fail') THEN 1 END) > 0
                    THEN 'FAIL'
                    ELSE 'PASS'
                END as status,
                COUNT(CASE WHEN status IN ('open', 'fail') THEN 1 END) as finding_count
            FROM control_data
            GROUP BY framework, control_id
            ORDER BY framework, control_id
        """)
        result = db.execute(query, {"framework": framework})
    else:
        query = text("""
            WITH control_data AS (
                SELECT
                    framework_key as framework,
                    control_id,
                    f.title as finding_title,
                    f.status,
                    f.severity
                FROM findings f,
                LATERAL jsonb_object_keys(f.compliance_frameworks) as framework_key,
                LATERAL jsonb_array_elements_text(f.compliance_frameworks->framework_key)
                    AS control_id
                WHERE f.compliance_frameworks IS NOT NULL
                  AND jsonb_typeof(f.compliance_frameworks) = 'object'
            )
            SELECT
                framework,
                control_id,
                MAX(finding_title) as control_title,
                NULL as requirement,
                MAX(severity) as severity,
                CASE
                    WHEN COUNT(CASE WHEN status IN ('open', 'fail') THEN 1 END) > 0
                    THEN 'FAIL'
                    ELSE 'PASS'
                END as status,
                COUNT(CASE WHEN status IN ('open', 'fail') THEN 1 END) as finding_count
            FROM control_data
            GROUP BY framework, control_id
            ORDER BY framework, control_id
        """)
        result = db.execute(query)

    rows = result.fetchall()

    # Build CSV
    output = StringIO()
    output.write(
        "Framework,Control ID,Control Title,Requirement,Severity,Status,Finding Count\n"
    )

    for row in rows:
        # Escape CSV fields
        framework_val = str(row[0] or "").replace('"', '""')
        control_id = str(row[1] or "").replace('"', '""')
        control_title = str(row[2] or "").replace('"', '""')
        requirement = str(row[3] or "").replace('"', '""')
        severity = str(row[4] or "").replace('"', '""')
        status = str(row[5] or "")
        finding_count = str(row[6] or 0)

        output.write(
            f'"{framework_val}","{control_id}","{control_title}",'
            f'"{requirement}","{severity}",{status},{finding_count}\n'
        )

    output.seek(0)

    # Sanitize framework name for filename (remove non-alphanumeric chars except dash)
    safe_framework = re.sub(r"[^\w\-]", "", framework) if framework else "all"
    filename = f"compliance-{safe_framework}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
