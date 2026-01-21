"""
Runtime Correlation API Endpoints.

This module provides endpoints for correlating security findings with CloudTrail
events, enabling runtime validation of theoretical vulnerabilities. It supports:

1. Triggering correlation analysis for findings, attack paths, and privesc paths
2. Retrieving correlations for specific findings
3. Getting suspicious CloudTrail events
4. Viewing findings confirmed by runtime evidence

Endpoints:
    POST /runtime/correlate - Trigger runtime correlation for findings/paths
    GET /runtime/correlations/{finding_id} - Get correlations for a finding
    GET /runtime/events/suspicious - Get suspicious CloudTrail events
    GET /runtime/events/confirmed-exploits - Get confirmed exploitable findings
"""

import logging
import sys
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models.database import AttackPath, Finding, PrivescPath, get_db

# Configure logging
logger = logging.getLogger(__name__)

router: APIRouter = APIRouter(prefix="/runtime", tags=["Runtime Correlation"])


# ============================================================================
# Pydantic Request/Response Models
# ============================================================================


class RuntimeCorrelateRequest(BaseModel):
    """Request to correlate with runtime events."""

    finding_ids: list[int] | None = Field(
        default=None, max_length=100, description="Finding IDs to correlate"
    )
    attack_path_ids: list[int] | None = Field(
        default=None, max_length=50, description="Attack path IDs to correlate"
    )
    privesc_path_ids: list[int] | None = Field(
        default=None, max_length=50, description="Privesc path IDs to correlate"
    )
    hours_back: int = Field(
        default=24, ge=1, le=168, description="Hours to look back in CloudTrail"
    )


class CloudTrailEvent(BaseModel):
    """CloudTrail event details."""

    event_id: str | None = None
    event_source: str | None = None
    event_name: str | None = None
    event_time: datetime | str | None = None
    source_ip: str | None = None
    user_identity: dict[str, Any] | None = None
    request_parameters: dict[str, Any] | None = None
    response_elements: dict[str, Any] | None = None


class RuntimeCorrelation(BaseModel):
    """A single runtime correlation."""

    correlation_id: str
    finding_id: int | None = None
    attack_path_id: int | None = None
    privesc_path_id: int | None = None
    event: CloudTrailEvent | dict[str, Any] | None = None
    correlation_type: str
    confidence_score: int = Field(ge=0, le=100)
    confirms_exploitability: bool = False
    anomaly_detected: bool = False
    analysis_notes: str | None = None


class RuntimeCorrelateResponse(BaseModel):
    """Response from runtime correlation."""

    cloudtrail_available: bool
    correlations_found: int
    findings_correlated: int
    paths_correlated: int
    confirmed_exploitable: int


class RuntimeCorrelationsResponse(BaseModel):
    """Response for finding correlations."""

    finding_id: int
    correlations: list[RuntimeCorrelation] = []
    runtime_confirmed: bool = False


class SuspiciousEvent(BaseModel):
    """A suspicious CloudTrail event."""

    event: CloudTrailEvent | dict[str, Any]
    suspicion_reasons: list[str] = []
    severity: str = "medium"


class RuntimeSuspiciousEventsResponse(BaseModel):
    """Response for suspicious events."""

    events: list[SuspiciousEvent] = []
    total: int = 0
    time_range_hours: int = 24


class ConfirmedExploit(BaseModel):
    """A finding confirmed by runtime events."""

    finding_id: int
    finding_title: str | None = None
    finding_severity: str | None = None
    finding_resource: str | None = None
    correlation: RuntimeCorrelation | dict[str, Any] | None = None
    confirmed_at: datetime | None = None


class RuntimeConfirmedExploitsResponse(BaseModel):
    """Response for confirmed exploits."""

    exploits: list[ConfirmedExploit] = []
    total: int = 0


# ============================================================================
# Helper Functions
# ============================================================================


def get_correlator():
    """Get RuntimeCorrelator instance."""
    try:
        sys.path.insert(0, "/app/report-processor")
        from runtime_correlator import RuntimeCorrelator

        return RuntimeCorrelator()
    except ImportError as e:
        logger.error(f"RuntimeCorrelator not available: {e}")
        return None


# ============================================================================
# API Endpoints
# ============================================================================


@router.post("/correlate", response_model=RuntimeCorrelateResponse)
async def correlate_with_runtime(
    request: RuntimeCorrelateRequest,
    db: Session = Depends(get_db),
):
    """
    Trigger runtime correlation for findings/paths.

    Correlates security findings, attack paths, and/or privilege escalation paths
    with CloudTrail events to validate exploitability with runtime evidence.

    Args:
        request: Correlation request with IDs to correlate.
        db: Database session.

    Returns:
        RuntimeCorrelateResponse: Summary of correlation results.

    Raises:
        HTTPException 500: If correlator is unavailable.
    """
    correlator = get_correlator()
    if not correlator:
        raise HTTPException(
            status_code=500,
            detail="Runtime correlator not available. Ensure report-processor is mounted.",
        )

    # Check CloudTrail availability
    cloudtrail_available = correlator._check_cloudtrail_access()

    correlations_found = 0
    findings_correlated = 0
    paths_correlated = 0
    confirmed_exploitable = 0

    # Correlate findings
    if request.finding_ids:
        for finding_id in request.finding_ids:
            # Verify finding exists
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                logger.warning(f"Finding {finding_id} not found, skipping")
                continue

            correlations = correlator.correlate_finding(finding_id)
            correlations_found += len(correlations)
            if correlations:
                findings_correlated += 1
                confirmed_exploitable += sum(
                    1 for c in correlations if c.get("confirms_exploitability")
                )

    # Correlate attack paths
    if request.attack_path_ids:
        for path_id in request.attack_path_ids:
            # Verify path exists
            path = db.query(AttackPath).filter(AttackPath.id == path_id).first()
            if not path:
                logger.warning(f"Attack path {path_id} not found, skipping")
                continue

            correlations = correlator.correlate_attack_path(path_id)
            correlations_found += len(correlations)
            if correlations:
                paths_correlated += 1
                confirmed_exploitable += sum(
                    1 for c in correlations if c.get("confirms_exploitability")
                )

    # Correlate privesc paths
    if request.privesc_path_ids:
        for path_id in request.privesc_path_ids:
            # Verify path exists
            path = db.query(PrivescPath).filter(PrivescPath.id == path_id).first()
            if not path:
                logger.warning(f"Privesc path {path_id} not found, skipping")
                continue

            correlations = correlator.correlate_privesc_path(path_id)
            correlations_found += len(correlations)
            if correlations:
                paths_correlated += 1
                confirmed_exploitable += sum(
                    1 for c in correlations if c.get("confirms_exploitability")
                )

    return RuntimeCorrelateResponse(
        cloudtrail_available=cloudtrail_available,
        correlations_found=correlations_found,
        findings_correlated=findings_correlated,
        paths_correlated=paths_correlated,
        confirmed_exploitable=confirmed_exploitable,
    )


@router.get("/correlations/{finding_id}", response_model=RuntimeCorrelationsResponse)
async def get_finding_correlations(
    finding_id: int,
    db: Session = Depends(get_db),
):
    """
    Get runtime correlations for a specific finding.

    Retrieves all CloudTrail events that have been correlated with this finding,
    including confidence scores and exploitability confirmation.

    Args:
        finding_id: Database ID of the finding.
        db: Database session.

    Returns:
        RuntimeCorrelationsResponse: Correlations for the finding.

    Raises:
        HTTPException 404: If finding is not found.
        HTTPException 500: If correlator is unavailable.
    """
    # Verify finding exists
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    correlator = get_correlator()
    if not correlator:
        raise HTTPException(
            status_code=500,
            detail="Runtime correlator not available. Ensure report-processor is mounted.",
        )

    correlations_data = correlator.get_correlations_for_finding(finding_id)

    # Convert to response model
    correlations = []
    runtime_confirmed = False

    for corr in correlations_data:
        event_data = corr.get("event_data") or {}
        correlation = RuntimeCorrelation(
            correlation_id=corr.get("correlation_id", ""),
            finding_id=corr.get("finding_id"),
            attack_path_id=corr.get("attack_path_id"),
            privesc_path_id=corr.get("privesc_path_id"),
            event=event_data,
            correlation_type=corr.get("correlation_type", "unknown"),
            confidence_score=corr.get("confidence_score", 50),
            confirms_exploitability=corr.get("confirms_exploitability", False),
            anomaly_detected=corr.get("anomaly_detected", False),
            analysis_notes=corr.get("analysis_notes"),
        )
        correlations.append(correlation)

        if corr.get("confirms_exploitability"):
            runtime_confirmed = True

    return RuntimeCorrelationsResponse(
        finding_id=finding_id,
        correlations=correlations,
        runtime_confirmed=runtime_confirmed,
    )


@router.get("/events/suspicious", response_model=RuntimeSuspiciousEventsResponse)
async def get_suspicious_events(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    db: Session = Depends(get_db),
):
    """
    Get suspicious events from CloudTrail.

    Fetches CloudTrail events from the specified time window and identifies
    suspicious activity such as off-hours access, unusual IPs, or root account usage.

    Args:
        hours: Number of hours to look back (1-168).
        db: Database session.

    Returns:
        RuntimeSuspiciousEventsResponse: List of suspicious events.

    Raises:
        HTTPException 500: If correlator is unavailable.
    """
    correlator = get_correlator()
    if not correlator:
        raise HTTPException(
            status_code=500,
            detail="Runtime correlator not available. Ensure report-processor is mounted.",
        )

    # Check CloudTrail access
    if not correlator._check_cloudtrail_access():
        return RuntimeSuspiciousEventsResponse(
            events=[],
            total=0,
            time_range_hours=hours,
        )

    suspicious_events = correlator.get_suspicious_events(hours=hours)

    # Convert to response model
    events = []
    for item in suspicious_events:
        event_data = item.get("event", {})
        events.append(
            SuspiciousEvent(
                event=event_data,
                suspicion_reasons=item.get("suspicion_reasons", []),
                severity=item.get("severity", "medium"),
            )
        )

    return RuntimeSuspiciousEventsResponse(
        events=events,
        total=len(events),
        time_range_hours=hours,
    )


@router.get("/events/confirmed-exploits", response_model=RuntimeConfirmedExploitsResponse)
async def get_confirmed_exploits(
    scan_id: str = Query(None, description="Filter by scan ID"),
    db: Session = Depends(get_db),
):
    """
    Get findings confirmed by runtime events.

    Retrieves findings that have been validated as exploitable through
    correlation with actual CloudTrail events showing the vulnerability
    being exercised or conditions that confirm the risk.

    Args:
        scan_id: Optional scan ID to filter by.
        db: Database session.

    Returns:
        RuntimeConfirmedExploitsResponse: List of confirmed exploits.

    Raises:
        HTTPException 500: If correlator is unavailable.
    """
    correlator = get_correlator()
    if not correlator:
        raise HTTPException(
            status_code=500,
            detail="Runtime correlator not available. Ensure report-processor is mounted.",
        )

    confirmed_data = correlator.get_confirmed_exploits(scan_id=scan_id)

    # Convert to response model
    exploits = []
    for item in confirmed_data:
        correlation_data = item.get("correlation", {})
        exploits.append(
            ConfirmedExploit(
                finding_id=item.get("finding_id"),
                finding_title=item.get("finding_title"),
                finding_severity=item.get("finding_severity"),
                finding_resource=item.get("finding_resource"),
                correlation=correlation_data,
                confirmed_at=item.get("confirmed_at"),
            )
        )

    return RuntimeConfirmedExploitsResponse(
        exploits=exploits,
        total=len(exploits),
    )


@router.get("/status")
async def get_runtime_status():
    """
    Get runtime correlation status.

    Returns the current status of the runtime correlation system,
    including CloudTrail availability and database connectivity.

    Returns:
        dict: Status information.
    """
    correlator = get_correlator()

    if not correlator:
        return {
            "status": "unavailable",
            "correlator_loaded": False,
            "cloudtrail_available": False,
            "message": "Runtime correlator module not loaded",
        }

    cloudtrail_available = correlator._check_cloudtrail_access()

    return {
        "status": "operational" if cloudtrail_available else "degraded",
        "correlator_loaded": True,
        "cloudtrail_available": cloudtrail_available,
        "message": (
            "Fully operational"
            if cloudtrail_available
            else "CloudTrail not accessible - correlation limited to database"
        ),
    }


# ============================================================================
# Pydantic Schemas for Later Integration
# ============================================================================
#
# The following schemas should be added to api/models/schemas.py when
# integrating this router into the main application:
#
# ```python
# # ============================================================================
# # Runtime Correlation Schemas
# # ============================================================================
#
# class CorrelationType(str, Enum):
#     privesc = "privesc"
#     data_access = "data_access"
#     credential_usage = "credential_usage"
#     resource_modification = "resource_modification"
#     secrets_access = "secrets_access"
#     lambda_execution = "lambda_execution"
#
#
# class RuntimeCorrelateRequest(BaseModel):
#     """Request to correlate with runtime events."""
#     finding_ids: list[int] | None = Field(default=None, max_length=100)
#     attack_path_ids: list[int] | None = Field(default=None, max_length=50)
#     privesc_path_ids: list[int] | None = Field(default=None, max_length=50)
#     hours_back: int = Field(default=24, ge=1, le=168, description="Hours to look back in CloudTrail")
#
#
# class CloudTrailEvent(BaseModel):
#     """CloudTrail event details."""
#     event_id: str | None = None
#     event_source: str | None = None
#     event_name: str | None = None
#     event_time: datetime | str | None = None
#     source_ip: str | None = None
#     user_identity: dict[str, Any] | None = None
#     request_parameters: dict[str, Any] | None = None
#     response_elements: dict[str, Any] | None = None
#
#
# class RuntimeCorrelation(BaseModel):
#     """A single runtime correlation."""
#     correlation_id: str
#     finding_id: int | None = None
#     attack_path_id: int | None = None
#     privesc_path_id: int | None = None
#     event: CloudTrailEvent | dict[str, Any] | None = None
#     correlation_type: str
#     confidence_score: int = Field(ge=0, le=100)
#     confirms_exploitability: bool = False
#     anomaly_detected: bool = False
#     analysis_notes: str | None = None
#
#
# class RuntimeCorrelateResponse(BaseModel):
#     """Response from runtime correlation."""
#     cloudtrail_available: bool
#     correlations_found: int
#     findings_correlated: int
#     paths_correlated: int
#     confirmed_exploitable: int
#
#
# class RuntimeCorrelationsResponse(BaseModel):
#     """Response for finding correlations."""
#     finding_id: int
#     correlations: list[RuntimeCorrelation] = []
#     runtime_confirmed: bool = False
#
#
# class SuspiciousEvent(BaseModel):
#     """A suspicious CloudTrail event."""
#     event: CloudTrailEvent | dict[str, Any]
#     suspicion_reasons: list[str] = []
#     severity: str = "medium"
#
#
# class RuntimeSuspiciousEventsResponse(BaseModel):
#     """Response for suspicious events."""
#     events: list[SuspiciousEvent] = []
#     total: int = 0
#     time_range_hours: int = 24
#
#
# class ConfirmedExploit(BaseModel):
#     """A finding confirmed by runtime events."""
#     finding_id: int
#     finding_title: str | None = None
#     finding_severity: str | None = None
#     finding_resource: str | None = None
#     correlation: RuntimeCorrelation | dict[str, Any] | None = None
#     confirmed_at: datetime | None = None
#
#
# class RuntimeConfirmedExploitsResponse(BaseModel):
#     """Response for confirmed exploits."""
#     exploits: list[ConfirmedExploit] = []
#     total: int = 0
# ```
#
# ============================================================================
