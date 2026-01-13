"""Pydantic schemas for API request/response models.

Security Notes:
- All string inputs have maximum length constraints to prevent DoS attacks
- Regex patterns validate format where applicable
- Enum types restrict values to known safe options
"""

import re
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


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

    profile: ScanProfile = Field(
        default=ScanProfile.comprehensive, description="Scan profile to use"
    )
    provider: str | None = Field(
        default=None,
        max_length=32,
        pattern=r"^(aws|azure|gcp|kubernetes|iac)$",
        description="Single provider to scan (aws, azure, gcp, kubernetes, iac)",
    )
    tools: list[str] | None = Field(
        default=None,
        max_length=20,
        description="Specific tools to run (overrides profile tools)",
    )
    target: str | None = Field(default=None, max_length=256, description="Specific target to scan")
    severity_filter: str | None = Field(
        default=None,
        max_length=100,
        pattern=r"^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$",
        description="Comma-separated severity levels",
    )
    dry_run: bool = Field(default=False, description="Preview commands without executing")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        """Validate target does not contain shell metacharacters."""
        if v is None:
            return v
        # Block shell metacharacters that could be used for injection
        dangerous_chars = ["|", "&", ";", "$", "`", "(", ")", "{", "}", "<", ">", "\n", "\r"]
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f"Invalid character in target: {char}")
        return v

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, v):
        """Validate tool names contain only safe characters."""
        if v is None:
            return v
        for tool in v:
            if not re.match(r"^[a-z0-9\-]+$", tool):
                raise ValueError(f"Invalid tool name format: {tool}")
        return v


class ScanResponse(BaseModel):
    """Response schema for scan details."""

    scan_id: UUID
    scan_type: str | None
    target: str | None
    tool: str | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Response schema for listing scans."""

    scans: list[ScanResponse]
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
    description: str | None = Field(default=None, description="What this command does")


class RemediationResource(BaseModel):
    """External resource for remediation guidance."""

    title: str = Field(description="Resource title")
    url: str = Field(description="Resource URL")
    type: str = Field(
        default="documentation", description="Resource type: documentation, blog, video"
    )


class AffectedResource(BaseModel):
    """Details of an affected resource."""

    id: str = Field(description="Resource ID")
    name: str | None = Field(default=None, description="Resource name")
    region: str | None = Field(default=None, description="Resource region")
    type: str | None = Field(default=None, description="Resource type")


class FindingResponse(BaseModel):
    """Response schema for finding details."""

    id: int
    finding_id: str | None
    scan_id: UUID | None
    tool: str | None
    cloud_provider: str | None
    account_id: str | None = Field(default=None, description="Cloud account ID")
    severity: str | None
    status: str = "open"
    title: str | None
    description: str | None
    remediation: str | None
    resource_type: str | None
    resource_id: str | None
    resource_name: str | None
    region: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    # Risk scoring fields
    risk_score: float | None = Field(default=None, description="CVSS-style risk score (0-100)")
    cvss_score: float | None = Field(default=None, description="CVSS base score (0-10)")
    exploitability: str | None = Field(
        default=None,
        description="Exploitation likelihood: confirmed, likely, theoretical, unlikely",
    )
    # Proof of Concept Evidence
    poc_evidence: str | None = Field(
        default=None, description="Raw evidence/API response demonstrating the finding"
    )
    poc_verification: str | None = Field(
        default=None, description="Command to verify the finding exists"
    )
    poc_screenshot_path: str | None = Field(default=None, description="Path to screenshot evidence")
    # Enhanced Remediation
    remediation_commands: list[RemediationCommand] | None = Field(
        default=None, description="CLI/IaC commands to fix"
    )
    remediation_code: dict[str, str] | None = Field(
        default=None, description="Code snippets by language/tool"
    )
    remediation_resources: list[RemediationResource] | None = Field(
        default=None, description="External documentation links"
    )
    # Deduplication fields
    canonical_id: str | None = Field(
        default=None, description="Canonical ID for grouping similar findings"
    )
    tool_sources: list[str] | None = Field(
        default=None, description="List of tools that detected this finding"
    )
    affected_resources: list[AffectedResource] | None = Field(
        default=None, description="List of affected resources"
    )
    affected_count: int | None = Field(default=None, description="Count of affected resources")

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Request schema for updating a finding."""

    status: FindingStatus | None = None
    tags: dict[str, Any] | None = Field(default=None, description="Custom tags for the finding")

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v):
        """Validate tags don't exceed limits and keys are safe."""
        if v is None:
            return v
        # Limit number of tags
        if len(v) > 50:
            raise ValueError("Maximum 50 tags allowed")
        # Validate tag keys and values
        for key, value in v.items():
            if not isinstance(key, str) or len(key) > 64:
                raise ValueError("Tag keys must be strings with max length 64")
            # Validate key contains only safe characters
            if not re.match(r"^[a-zA-Z0-9_\-\.]+$", key):
                raise ValueError(f"Invalid tag key format: {key}")
            # Limit value size
            if isinstance(value, str) and len(value) > 256:
                raise ValueError(f"Tag value for '{key}' exceeds 256 characters")
        return v


class FindingListResponse(BaseModel):
    """Response schema for listing findings."""

    findings: list[FindingResponse]
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
    by_provider: dict[str, int] = {}
    by_tool: dict[str, int] = {}


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
    message: str | None = None
    latency_ms: float | None = Field(default=None, description="Response time in milliseconds")
    details: dict[str, Any] | None = Field(default=None, description="Additional service details")


class DependencyHealth(BaseModel):
    """Health status for a dependency."""

    name: str
    status: str = Field(description="healthy, unhealthy, or degraded")
    latency_ms: float | None = None
    version: str | None = None
    message: str | None = None
    last_check: datetime


class DetailedHealthResponse(BaseModel):
    """Detailed health check response with all dependencies."""

    status: str = Field(description="Overall status: healthy, degraded, or unhealthy")
    services: list[ServiceStatus]
    timestamp: datetime
    uptime_seconds: float | None = Field(default=None, description="API uptime in seconds")
    request_id: str | None = Field(default=None, description="Current request correlation ID")


class LivenessResponse(BaseModel):
    """Kubernetes liveness probe response."""

    status: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    """Kubernetes readiness probe response."""

    ready: bool
    status: str
    checks: dict[str, bool] = Field(description="Individual readiness checks")
    timestamp: datetime


# ============================================================================
# Export Schemas
# ============================================================================


class ExportFormat(str, Enum):
    """Allowed export formats."""

    csv = "csv"
    json = "json"


class ExportRequest(BaseModel):
    """Request schema for generating exports."""

    format: ExportFormat = Field(default=ExportFormat.csv, description="Export format: csv, json")
    severity_filter: list[SeverityLevel] | None = None
    cloud_provider: str | None = Field(
        default=None,
        max_length=32,
        pattern=r"^[a-z0-9\-]+$",
        description="Cloud provider filter (aws, azure, gcp, kubernetes)",
    )
    status_filter: list[FindingStatus] | None = None
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
    resource_id: str | None = None
    region: str | None = None


class AttackPathEdge(BaseModel):
    """Edge in an attack path."""

    id: str
    source: str
    target: str
    type: str
    name: str
    finding_id: int | None = None
    exploitability: str = "theoretical"
    impact: str = "medium"


class PoCStep(BaseModel):
    """Single step in a Proof of Concept."""

    step: int
    name: str
    description: str
    command: str
    mitre_technique: str | None = None
    requires_auth: bool = False


class AttackPathResponse(BaseModel):
    """Response schema for attack path details."""

    id: int
    path_id: str
    scan_id: UUID | None = None
    name: str
    description: str | None = None
    entry_point_type: str
    entry_point_id: str | None = None
    entry_point_name: str | None = None
    target_type: str
    target_description: str | None = None
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]
    finding_ids: list[int] = []
    risk_score: int
    exploitability: str
    impact: str
    hop_count: int
    requires_authentication: bool = False
    requires_privileges: bool = False
    poc_available: bool = False
    poc_steps: list[PoCStep] = []
    mitre_tactics: list[str] = []
    aws_services: list[str] = []
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class AttackPathListResponse(BaseModel):
    """Response schema for listing attack paths."""

    paths: list[AttackPathResponse]
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
    entry_point_types: dict[str, int] = {}
    target_types: dict[str, int] = {}
    top_mitre_tactics: list[str] = []
    avg_risk_score: float = 0.0


class AttackPathAnalyzeRequest(BaseModel):
    """Request to trigger attack path analysis."""

    scan_id: UUID | None = Field(default=None, description="Specific scan to analyze")
    max_depth: int = Field(default=5, ge=1, le=10, description="Maximum path depth")


class AttackPathAnalyzeResponse(BaseModel):
    """Response from attack path analysis."""

    paths_discovered: int
    analysis_time_ms: int
    summary: AttackPathSummary


# ============================================================================
# Public Exposure Schemas
# ============================================================================


class PublicExposureResponse(BaseModel):
    """Response schema for public exposure details."""

    id: int
    exposure_id: str
    scan_id: UUID | None = None
    cloud_provider: str
    account_id: str | None = None
    region: str | None = None
    resource_type: str
    resource_id: str | None = None
    resource_name: str | None = None
    exposure_type: str
    exposure_details: dict[str, Any] | None = None
    risk_level: str = "medium"
    protocol: str | None = None
    port_range: str | None = None
    source_cidr: str | None = None
    is_internet_exposed: bool = False
    finding_ids: list[int] | None = None
    tags: dict[str, Any] | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: str = "open"

    class Config:
        from_attributes = True


class PublicExposureListResponse(BaseModel):
    """Response schema for listing public exposures."""

    exposures: list[PublicExposureResponse]
    total: int
    page: int
    page_size: int


class PublicExposureSummary(BaseModel):
    """Summary of public exposures."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    internet_exposed: int = 0
    by_type: dict[str, int] = {}
    by_provider: dict[str, int] = {}


# ============================================================================
# Exposed Credential Schemas
# ============================================================================


class ExposedCredentialResponse(BaseModel):
    """Response schema for exposed credential details."""

    id: int
    credential_id: str
    scan_id: UUID | None = None
    cloud_provider: str
    account_id: str | None = None
    region: str | None = None
    source_type: str
    source_location: str | None = None
    credential_type: str
    credential_name: str | None = None
    is_active: bool = True
    risk_level: str = "critical"
    finding_ids: list[int] | None = None
    discovered_by: str | None = None
    remediation_status: str = "pending"
    remediation_notes: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    class Config:
        from_attributes = True


class ExposedCredentialListResponse(BaseModel):
    """Response schema for listing exposed credentials."""

    credentials: list[ExposedCredentialResponse]
    total: int
    page: int
    page_size: int


class ExposedCredentialSummary(BaseModel):
    """Summary of exposed credentials."""

    total: int = 0
    active: int = 0
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_provider: dict[str, int] = {}


class CredentialRemediationUpdate(BaseModel):
    """Request to update credential remediation status."""

    remediation_status: str = Field(description="Status: pending, in_progress, resolved, accepted")
    remediation_notes: str | None = None


# ============================================================================
# Severity Override Schemas
# ============================================================================


class SeverityOverrideCreate(BaseModel):
    """Request schema for creating a severity override."""

    finding_id: int
    new_severity: str = Field(description="New severity: critical, high, medium, low, info")
    justification: str = Field(min_length=10, description="Justification for the override")
    created_by: str | None = None
    expires_at: datetime | None = None


class SeverityOverrideResponse(BaseModel):
    """Response schema for severity override details."""

    id: int
    finding_id: int
    original_severity: str
    new_severity: str
    justification: str
    override_type: str = "manual"
    created_by: str | None = None
    approved_by: str | None = None
    approval_status: str = "pending"
    expires_at: datetime | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class SeverityOverrideListResponse(BaseModel):
    """Response schema for listing severity overrides."""

    overrides: list[SeverityOverrideResponse]
    total: int
    page: int
    page_size: int


class SeverityOverrideApproval(BaseModel):
    """Request to approve or reject a severity override."""

    approved: bool
    approved_by: str
    notes: str | None = None


# ============================================================================
# Privilege Escalation Path Schemas
# ============================================================================


class PrivescPathNode(BaseModel):
    """Node in a privilege escalation path."""

    id: str
    type: str
    name: str
    arn: str | None = None
    permissions: list[str] | None = None


class PrivescPathEdge(BaseModel):
    """Edge in a privilege escalation path."""

    id: str
    source: str
    target: str
    method: str
    description: str | None = None
    requires_condition: bool = False


class PrivescPathResponse(BaseModel):
    """Response schema for privilege escalation path details."""

    id: int
    path_id: str
    scan_id: UUID | None = None
    cloud_provider: str
    account_id: str | None = None
    source_principal_type: str
    source_principal_arn: str | None = None
    source_principal_name: str | None = None
    target_principal_type: str
    target_principal_arn: str | None = None
    target_principal_name: str | None = None
    escalation_method: str
    escalation_details: dict[str, Any] | None = None
    path_nodes: list[PrivescPathNode] | None = []
    path_edges: list[PrivescPathEdge] | None = []
    risk_score: int = 0
    exploitability: str = "theoretical"
    requires_conditions: dict[str, Any] | None = None
    mitre_techniques: list[str] | None = None
    poc_commands: list[dict[str, str]] | None = None
    finding_ids: list[int] | None = None
    status: str = "open"
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class PrivescPathListResponse(BaseModel):
    """Response schema for listing privilege escalation paths."""

    paths: list[PrivescPathResponse]
    total: int
    page: int
    page_size: int


class PrivescPathSummary(BaseModel):
    """Summary of privilege escalation paths."""

    total_paths: int = 0
    critical_paths: int = 0
    high_risk_paths: int = 0
    by_method: dict[str, int] = {}
    by_target: dict[str, int] = {}


class PrivescPathAnalyzeRequest(BaseModel):
    """Request to trigger privilege escalation path analysis."""

    scan_id: UUID | None = Field(default=None, description="Specific scan to analyze")


class PrivescPathAnalyzeResponse(BaseModel):
    """Response from privilege escalation path analysis."""

    paths_discovered: int
    analysis_time_ms: int
    summary: PrivescPathSummary


# ============================================================================
# IMDS Check Schemas
# ============================================================================


class ImdsCheckResponse(BaseModel):
    """Response schema for IMDS check details."""

    id: int
    check_id: str
    scan_id: UUID | None = None
    cloud_provider: str
    account_id: str | None = None
    region: str | None = None
    instance_id: str | None = None
    instance_name: str | None = None
    imds_version: str | None = None
    imds_v1_enabled: bool = False
    imds_hop_limit: int | None = None
    http_endpoint_enabled: bool = True
    http_tokens_required: bool = False
    ssrf_vulnerable: bool = False
    container_credential_exposure: bool = False
    ecs_task_role_exposed: bool = False
    eks_pod_identity_exposed: bool = False
    vulnerability_details: dict[str, Any] | None = None
    risk_level: str = "medium"
    finding_ids: list[int] | None = None
    remediation_status: str = "pending"
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class ImdsCheckListResponse(BaseModel):
    """Response schema for listing IMDS checks."""

    checks: list[ImdsCheckResponse]
    total: int
    page: int
    page_size: int


class ImdsCheckSummary(BaseModel):
    """Summary of IMDS checks."""

    total_instances: int = 0
    imds_v1_enabled: int = 0
    ssrf_vulnerable: int = 0
    container_exposed: int = 0
    by_region: dict[str, int] = {}


# ============================================================================
# CloudFox Schemas
# ============================================================================


class CloudfoxResultResponse(BaseModel):
    """Response schema for CloudFox result details."""

    id: int
    result_id: str
    scan_id: UUID | None = None
    cloud_provider: str
    account_id: str | None = None
    region: str | None = None
    module_name: str
    result_type: str | None = None
    resource_arn: str | None = None
    resource_name: str | None = None
    finding_category: str | None = None
    finding_details: dict[str, Any] | None = None
    risk_level: str = "medium"
    loot_file_path: str | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class CloudfoxResultListResponse(BaseModel):
    """Response schema for listing CloudFox results."""

    results: list[CloudfoxResultResponse]
    total: int
    page: int
    page_size: int


class CloudfoxSummary(BaseModel):
    """Summary of CloudFox results."""

    total_results: int = 0
    by_module: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_risk: dict[str, int] = {}


class CloudfoxRunRequest(BaseModel):
    """Request to run CloudFox modules."""

    modules: list[str] = Field(default=["all"], description="Modules to run")
    profile: str | None = None
    regions: list[str] | None = None


# ============================================================================
# Pacu Schemas
# ============================================================================


class PacuResultResponse(BaseModel):
    """Response schema for Pacu result details."""

    id: int
    result_id: str
    scan_id: UUID | None = None
    session_name: str | None = None
    module_name: str
    module_category: str | None = None
    execution_status: str | None = None
    target_account_id: str | None = None
    target_region: str | None = None
    resources_affected: int = 0
    permissions_used: list[str] | None = None
    findings: list[dict[str, Any]] | None = None
    loot_data: dict[str, Any] | None = None
    error_message: str | None = None
    execution_time_ms: int | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class PacuResultListResponse(BaseModel):
    """Response schema for listing Pacu results."""

    results: list[PacuResultResponse]
    total: int
    page: int
    page_size: int


class PacuSummary(BaseModel):
    """Summary of Pacu results."""

    total_executions: int = 0
    successful: int = 0
    failed: int = 0
    by_module: dict[str, int] = {}
    by_category: dict[str, int] = {}


class PacuRunRequest(BaseModel):
    """Request to run Pacu modules."""

    module: str = Field(description="Module to execute")
    session_name: str | None = None
    args: dict[str, Any] | None = None
    # AWS credentials
    access_key: str | None = None
    secret_key: str | None = None
    session_token: str | None = None
    region: str | None = None


# ============================================================================
# enumerate-iam Schemas
# ============================================================================


class EnumerateIamResultResponse(BaseModel):
    """Response schema for enumerate-iam result details."""

    id: int
    result_id: str
    scan_id: UUID | None = None
    account_id: str | None = None
    principal_arn: str | None = None
    principal_name: str | None = None
    principal_type: str | None = None
    enumeration_method: str | None = None
    confirmed_permissions: list[str] | None = None
    denied_permissions: list[str] | None = None
    error_permissions: list[str] | None = None
    permission_count: int = 0
    high_risk_permissions: list[str] | None = None
    privesc_capable: bool = False
    data_access_capable: bool = False
    admin_capable: bool = False
    enumeration_duration_ms: int | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class EnumerateIamListResponse(BaseModel):
    """Response schema for listing enumerate-iam results."""

    results: list[EnumerateIamResultResponse]
    total: int
    page: int
    page_size: int


class EnumerateIamSummary(BaseModel):
    """Summary of enumerate-iam results."""

    total_principals: int = 0
    privesc_capable: int = 0
    admin_capable: int = 0
    data_access_capable: int = 0
    avg_permissions: float = 0.0


class EnumerateIamRunRequest(BaseModel):
    """Request to run enumerate-iam."""

    access_key: str | None = None
    secret_key: str | None = None
    session_token: str | None = None
    profile: str | None = None
    region: str | None = None


# ============================================================================
# Assumed Role Mapping Schemas
# ============================================================================


class AssumedRoleMappingResponse(BaseModel):
    """Response schema for assumed role mapping details."""

    id: int
    mapping_id: str
    scan_id: UUID | None = None
    cloud_provider: str
    account_id: str | None = None
    source_principal_type: str
    source_principal_arn: str | None = None
    source_principal_name: str | None = None
    source_account_id: str | None = None
    target_role_arn: str
    target_role_name: str | None = None
    target_account_id: str | None = None
    trust_policy: dict[str, Any] | None = None
    conditions: dict[str, Any] | None = None
    is_cross_account: bool = False
    is_external_id_required: bool = False
    max_session_duration: int | None = None
    assumption_chain_depth: int = 1
    risk_level: str = "medium"
    neo4j_synced: bool = False
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class AssumedRoleMappingListResponse(BaseModel):
    """Response schema for listing assumed role mappings."""

    mappings: list[AssumedRoleMappingResponse]
    total: int
    page: int
    page_size: int


class AssumedRoleSummary(BaseModel):
    """Summary of assumed role mappings."""

    total_mappings: int = 0
    cross_account: int = 0
    external_id_required: int = 0
    by_source_type: dict[str, int] = {}
    by_risk: dict[str, int] = {}


class Neo4jSyncRequest(BaseModel):
    """Request to sync role mappings to Neo4j."""

    mapping_ids: list[int] | None = None
    sync_all: bool = False


# ============================================================================
# Lambda Analysis Schemas
# ============================================================================


class SecretFinding(BaseModel):
    """A secret found in Lambda code."""

    type: str
    value_preview: str = Field(description="Redacted preview of the value")
    location: str
    line_number: int | None = None
    confidence: str = "high"


class VulnerableDependency(BaseModel):
    """A vulnerable dependency in Lambda."""

    package: str
    version: str
    vulnerability: str
    severity: str
    cve: str | None = None


class InsecurePattern(BaseModel):
    """An insecure code pattern found."""

    pattern_type: str
    description: str
    location: str
    line_number: int | None = None
    recommendation: str


class LambdaAnalysisResponse(BaseModel):
    """Response schema for Lambda analysis details."""

    id: int
    analysis_id: str
    scan_id: UUID | None = None
    cloud_provider: str = "aws"
    account_id: str | None = None
    region: str | None = None
    function_arn: str | None = None
    function_name: str | None = None
    runtime: str | None = None
    handler: str | None = None
    code_size_bytes: int | None = None
    memory_size: int | None = None
    timeout_seconds: int | None = None
    environment_variables: dict[str, str] | None = None
    has_vpc_config: bool = False
    layers: list[str] | None = None
    secrets_found: list[SecretFinding] | None = None
    hardcoded_credentials: list[dict[str, Any]] | None = None
    vulnerable_dependencies: list[VulnerableDependency] | None = None
    insecure_patterns: list[InsecurePattern] | None = None
    api_keys_exposed: list[dict[str, Any]] | None = None
    database_connections: list[dict[str, Any]] | None = None
    external_urls: list[str] | None = None
    risk_score: int = 0
    risk_level: str = "medium"
    finding_ids: list[int] | None = None
    analysis_status: str = "pending"
    analysis_error: str | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class LambdaAnalysisListResponse(BaseModel):
    """Response schema for listing Lambda analyses."""

    analyses: list[LambdaAnalysisResponse]
    total: int
    page: int
    page_size: int


class LambdaAnalysisSummary(BaseModel):
    """Summary of Lambda analyses."""

    total_functions: int = 0
    functions_with_secrets: int = 0
    functions_with_vulns: int = 0
    high_risk: int = 0
    by_runtime: dict[str, int] = {}
    by_region: dict[str, int] = {}


class LambdaAnalyzeRequest(BaseModel):
    """Request to analyze Lambda functions."""

    function_arns: list[str] | None = None
    regions: list[str] | None = None
    analyze_all: bool = False
    # AWS credentials
    access_key: str | None = None
    secret_key: str | None = None
    session_token: str | None = None
    region: str | None = None


# ============================================================================
# Tool Execution Schemas
# ============================================================================


class ToolExecutionStatus(str, Enum):
    """Tool execution status."""

    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ToolExecutionResponse(BaseModel):
    """Response schema for tool execution details."""

    id: int
    execution_id: str
    tool_name: str
    tool_type: str
    status: str
    container_id: str | None = None
    config: dict[str, Any] | None = None
    output_path: str | None = None
    error_message: str | None = None
    exit_code: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class ToolExecutionListResponse(BaseModel):
    """Response schema for listing tool executions."""

    executions: list[ToolExecutionResponse]
    total: int
    page: int
    page_size: int


class ToolExecutionStartResponse(BaseModel):
    """Response schema for starting a tool execution."""

    execution_id: str
    tool_name: str
    status: str
    message: str
    container_id: str | None = None
    error: str | None = None


class ToolExecutionLogsResponse(BaseModel):
    """Response schema for tool execution logs."""

    execution_id: str
    logs: str
    status: str


# ============================================================================
# Settings Schemas
# ============================================================================


class SettingCategory(str, Enum):
    """Setting categories."""

    scans = "scans"
    data = "data"
    notifications = "notifications"
    display = "display"


class UserSettingResponse(BaseModel):
    """Response schema for a single user setting."""

    id: int
    setting_key: str
    setting_value: Any
    category: str
    description: str | None = None
    updated_at: datetime | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class UserSettingListResponse(BaseModel):
    """Response schema for listing user settings."""

    settings: list[UserSettingResponse]
    total: int


class UserSettingsByCategory(BaseModel):
    """Settings grouped by category."""

    scans: dict[str, Any] = {}
    data: dict[str, Any] = {}
    notifications: dict[str, Any] = {}
    display: dict[str, Any] = {}


class UserSettingUpdate(BaseModel):
    """Request schema for updating a setting."""

    value: Any = Field(description="The new value for the setting")


class UserSettingCreate(BaseModel):
    """Request schema for creating a new setting."""

    setting_key: str = Field(max_length=128, pattern=r"^[a-z0-9_]+$")
    setting_value: Any
    category: SettingCategory
    description: str | None = Field(default=None, max_length=512)


class SettingsResetResponse(BaseModel):
    """Response after resetting settings."""

    message: str
    settings_reset: int


# ============================================================================
# Credential Status Cache Schemas
# ============================================================================


class CredentialStatusResponse(BaseModel):
    """Response schema for credential status cache."""

    id: int
    provider: str
    status: str
    identity: str | None = None
    account_info: str | None = None
    tools_ready: list[str] | None = []
    tools_partial: list[str] | None = []
    tools_failed: list[str] | None = []
    last_verified: datetime | None = None
    verification_error: str | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class CredentialStatusListResponse(BaseModel):
    """Response schema for listing all credential statuses."""

    statuses: list[CredentialStatusResponse]
    summary: dict[str, str] = Field(description="Provider -> status mapping")


# ============================================================================
# Compliance Schemas
# ============================================================================


class ComplianceControl(BaseModel):
    """Individual compliance control with pass/fail status."""

    control_id: str
    control_title: str | None = None
    control_description: str | None = None
    requirement: str | None = None
    severity: str | None = None
    status: str  # "pass" or "fail"
    finding_count: int = 0


class ComplianceFrameworkSummary(BaseModel):
    """Summary statistics for a compliance framework."""

    framework: str
    controls_checked: int
    controls_passed: int
    controls_failed: int
    pass_percentage: float
    open_findings: int


class ComplianceFrameworksResponse(BaseModel):
    """Response schema for listing all compliance frameworks."""

    frameworks: list[ComplianceFrameworkSummary]
    total: int


class ComplianceFrameworkDetail(BaseModel):
    """Detailed view of a compliance framework with all controls."""

    framework: str
    controls: list[ComplianceControl]
    summary: ComplianceFrameworkSummary


class ComplianceSummaryResponse(BaseModel):
    """High-level compliance summary across all frameworks."""

    frameworks_count: int
    total_controls: int
    total_passed: int
    total_failed: int
    overall_pass_percentage: float
    by_framework: list[ComplianceFrameworkSummary]


class ComplianceAffectedResource(BaseModel):
    """Resource that failed a compliance control."""

    resource_id: str
    resource_type: str | None = None
    resource_name: str | None = None
    region: str | None = None
    account_id: str | None = None
    status: str  # "fail", "open"
    reason: str | None = None  # Why it failed


class ComplianceControlDetail(BaseModel):
    """Detailed compliance control with affected resources and remediation."""

    control_id: str
    control_title: str | None = None
    control_description: str | None = None
    requirement: str | None = None
    framework: str
    severity: str | None = None
    status: str  # "pass" or "fail"
    affected_resources: list[ComplianceAffectedResource] = []
    total_resources_checked: int = 0
    resources_passed: int = 0
    resources_failed: int = 0
    remediation_guidance: str | None = None
    remediation_cli: str | None = None  # AWS CLI command if applicable
    reference_url: str | None = None
