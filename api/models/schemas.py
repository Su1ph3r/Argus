"""Pydantic schemas for API request/response models."""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity level enumeration."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class FindingStatus(str, Enum):
    """Finding status enumeration."""
    open = "open"
    closed = "closed"
    mitigated = "mitigated"
    accepted = "accepted"


class ScanProfile(str, Enum):
    """Available scan profiles."""
    quick = "quick"
    comprehensive = "comprehensive"
    compliance_only = "compliance-only"


# ============================================================================
# Scan Schemas
# ============================================================================

class ScanCreate(BaseModel):
    """Request schema for creating a new scan."""
    profile: ScanProfile = Field(default=ScanProfile.comprehensive, description="Scan profile to use")
    target: Optional[str] = Field(default=None, description="Specific target to scan")
    severity_filter: Optional[str] = Field(default=None, description="Comma-separated severity levels")
    dry_run: bool = Field(default=False, description="Preview commands without executing")


class ScanResponse(BaseModel):
    """Response schema for scan details."""
    scan_id: UUID
    scan_type: Optional[str]
    target: Optional[str]
    tool: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Response schema for listing scans."""
    scans: List[ScanResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# Finding Schemas
# ============================================================================

class RemediationCommand(BaseModel):
    """Remediation command details."""
    type: str = Field(description="Command type: cli, terraform, etc.")
    command: str = Field(description="The actual command to execute")
    description: Optional[str] = Field(default=None, description="What this command does")


class RemediationResource(BaseModel):
    """External resource for remediation guidance."""
    title: str = Field(description="Resource title")
    url: str = Field(description="Resource URL")
    type: str = Field(default="documentation", description="Resource type: documentation, blog, video")


class AffectedResource(BaseModel):
    """Details of an affected resource."""
    id: str = Field(description="Resource ID")
    name: Optional[str] = Field(default=None, description="Resource name")
    region: Optional[str] = Field(default=None, description="Resource region")
    type: Optional[str] = Field(default=None, description="Resource type")


class FindingResponse(BaseModel):
    """Response schema for finding details."""
    id: int
    finding_id: Optional[str]
    scan_id: Optional[UUID]
    tool: Optional[str]
    cloud_provider: Optional[str]
    account_id: Optional[str] = Field(default=None, description="Cloud account ID")
    severity: Optional[str]
    status: str = "open"
    title: Optional[str]
    description: Optional[str]
    remediation: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    resource_name: Optional[str]
    region: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    # Proof of Concept Evidence
    poc_evidence: Optional[str] = Field(default=None, description="Raw evidence/API response demonstrating the finding")
    poc_verification: Optional[str] = Field(default=None, description="Command to verify the finding exists")
    poc_screenshot_path: Optional[str] = Field(default=None, description="Path to screenshot evidence")
    # Enhanced Remediation
    remediation_commands: Optional[List[RemediationCommand]] = Field(default=None, description="CLI/IaC commands to fix")
    remediation_code: Optional[Dict[str, str]] = Field(default=None, description="Code snippets by language/tool")
    remediation_resources: Optional[List[RemediationResource]] = Field(default=None, description="External documentation links")
    # Deduplication fields
    canonical_id: Optional[str] = Field(default=None, description="Canonical ID for grouping similar findings")
    tool_sources: Optional[List[str]] = Field(default=None, description="List of tools that detected this finding")
    affected_resources: Optional[List[AffectedResource]] = Field(default=None, description="List of affected resources")
    affected_count: Optional[int] = Field(default=None, description="Count of affected resources")

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Request schema for updating a finding."""
    status: Optional[FindingStatus] = None
    tags: Optional[Dict[str, Any]] = None


class FindingListResponse(BaseModel):
    """Response schema for listing findings."""
    findings: List[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingSummary(BaseModel):
    """Summary of findings by severity."""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    by_provider: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}


# ============================================================================
# Health Schemas
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    database: str
    timestamp: datetime
    version: str = "1.0.0"


class ServiceStatus(BaseModel):
    """Individual service status."""
    name: str
    status: str
    message: Optional[str] = None


class DetailedHealthResponse(BaseModel):
    """Detailed health check response."""
    status: str
    services: List[ServiceStatus]
    timestamp: datetime


# ============================================================================
# Export Schemas
# ============================================================================

class ExportRequest(BaseModel):
    """Request schema for generating exports."""
    format: str = Field(default="csv", description="Export format: csv, json")
    severity_filter: Optional[List[SeverityLevel]] = None
    cloud_provider: Optional[str] = None
    status_filter: Optional[List[FindingStatus]] = None
    include_remediation: bool = True


class ExportResponse(BaseModel):
    """Response schema for export generation."""
    export_id: str
    filename: str
    format: str
    record_count: int
    download_url: str
    generated_at: datetime


# ============================================================================
# Attack Path Schemas
# ============================================================================

class AttackPathNode(BaseModel):
    """Node in an attack path."""
    id: str
    type: str = Field(description="Node type: entry_point, resource, or target")
    name: str
    resource_id: Optional[str] = None
    region: Optional[str] = None


class AttackPathEdge(BaseModel):
    """Edge in an attack path."""
    id: str
    source: str
    target: str
    type: str
    name: str
    finding_id: Optional[int] = None
    exploitability: str = "theoretical"
    impact: str = "medium"


class PoCStep(BaseModel):
    """Single step in a Proof of Concept."""
    step: int
    name: str
    description: str
    command: str
    mitre_technique: Optional[str] = None
    requires_auth: bool = False


class AttackPathResponse(BaseModel):
    """Response schema for attack path details."""
    id: int
    path_id: str
    scan_id: Optional[UUID] = None
    name: str
    description: Optional[str] = None
    entry_point_type: str
    entry_point_id: Optional[str] = None
    entry_point_name: Optional[str] = None
    target_type: str
    target_description: Optional[str] = None
    nodes: List[AttackPathNode]
    edges: List[AttackPathEdge]
    finding_ids: List[int] = []
    risk_score: int
    exploitability: str
    impact: str
    hop_count: int
    requires_authentication: bool = False
    requires_privileges: bool = False
    poc_available: bool = False
    poc_steps: List[PoCStep] = []
    mitre_tactics: List[str] = []
    aws_services: List[str] = []
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AttackPathListResponse(BaseModel):
    """Response schema for listing attack paths."""
    paths: List[AttackPathResponse]
    total: int
    page: int
    page_size: int


class AttackPathSummary(BaseModel):
    """Summary statistics for attack paths."""
    total_paths: int = 0
    critical_paths: int = 0
    high_risk_paths: int = 0
    medium_risk_paths: int = 0
    low_risk_paths: int = 0
    entry_point_types: Dict[str, int] = {}
    target_types: Dict[str, int] = {}
    top_mitre_tactics: List[str] = []
    avg_risk_score: float = 0.0


class AttackPathAnalyzeRequest(BaseModel):
    """Request to trigger attack path analysis."""
    scan_id: Optional[UUID] = Field(default=None, description="Specific scan to analyze")
    max_depth: int = Field(default=5, ge=1, le=10, description="Maximum path depth")


class AttackPathAnalyzeResponse(BaseModel):
    """Response from attack path analysis."""
    paths_discovered: int
    analysis_time_ms: int
    summary: AttackPathSummary
