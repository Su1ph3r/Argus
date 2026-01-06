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

class FindingResponse(BaseModel):
    """Response schema for finding details."""
    id: int
    finding_id: Optional[str]
    scan_id: Optional[UUID]
    tool: Optional[str]
    cloud_provider: Optional[str]
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
