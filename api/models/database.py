"""Database connection and SQLAlchemy models."""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    create_engine,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from config import get_settings

settings = get_settings()

# Create engine
engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=20)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """Dependency for getting database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Scan(Base):
    """Scan metadata model."""

    __tablename__ = "scans"

    scan_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_type = Column(String(64))
    target = Column(String(256))
    tool = Column(String(64))
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    status = Column(String(32), default="running")
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    scan_metadata = Column("metadata", JSONB)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    findings = relationship("Finding", back_populates="scan")
    files = relationship("ScanFile", back_populates="scan", cascade="all, delete-orphan")


class ScanFile(Base):
    """Scan file tracking model for bulk delete/archive operations."""

    __tablename__ = "scan_files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    tool = Column(String(64), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_type = Column(String(32), nullable=False)
    file_size_bytes = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="files")


class Finding(Base):
    """Security finding model."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(256), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    tool = Column(String(64))
    cloud_provider = Column(String(32))
    severity = Column(String(16))
    status = Column(String(32), default="open")
    title = Column(Text)
    description = Column(Text)
    remediation = Column(Text)
    resource_type = Column(String(128))
    resource_id = Column(String(256))
    resource_name = Column(String(256))
    account_id = Column(String(64))
    region = Column(String(64))
    risk_score = Column(Numeric(4, 2))
    cvss_score = Column(Numeric(3, 1))
    exploitability = Column(String(32), default="likely")
    cve_id = Column(String(32))
    compliance_frameworks = Column(JSONB)
    tags = Column(JSONB)
    finding_metadata = Column("metadata", JSONB)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    scan_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # PoC evidence fields
    poc_evidence = Column(Text)
    poc_verification = Column(Text)
    poc_screenshot_path = Column(Text)
    # Remediation fields
    remediation_commands = Column(JSONB)
    remediation_code = Column(JSONB)
    remediation_resources = Column(JSONB)
    # Impact field
    impact = Column(Text)
    # Deduplication fields
    canonical_id = Column(String(256))
    tool_sources = Column(JSONB, default=[])
    affected_resources = Column(JSONB, default=[])
    # Enhanced scoring fields (Phase 1)
    asset_criticality = Column(String(16), default="medium")
    blast_radius = Column(Integer, default=1)
    recurrence_count = Column(Integer, default=1)
    scoring_factors = Column(JSONB, default={})
    # Threat intelligence fields (Phase 1)
    threat_intel_enrichment = Column(JSONB, default=None)
    threat_intel_last_checked = Column(DateTime)

    scan = relationship("Scan", back_populates="findings")


class Asset(Base):
    """Cloud asset model."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(String(256), unique=True)
    cloud_provider = Column(String(32))
    account_id = Column(String(64))
    region = Column(String(64))
    asset_type = Column(String(128))
    asset_name = Column(String(256))
    tags = Column(JSONB)
    asset_metadata = Column("metadata", JSONB)
    security_findings_count = Column(Integer, default=0)
    last_scanned = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AttackPath(Base):
    """Attack path model for penetration testing analysis."""

    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    path_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    name = Column(String(256))
    description = Column(Text)
    entry_point_type = Column(String(64))
    entry_point_id = Column(String(512))
    entry_point_name = Column(String(256))
    target_type = Column(String(64))
    target_description = Column(String(256))
    nodes = Column(JSONB)
    edges = Column(JSONB)
    finding_ids = Column(JSONB)  # Array stored as JSONB
    risk_score = Column(Integer, default=0)
    exploitability = Column(String(32), default="theoretical")
    impact = Column(String(32), default="medium")
    hop_count = Column(Integer, default=0)
    requires_authentication = Column(Boolean, default=False)
    requires_privileges = Column(Boolean, default=False)
    poc_available = Column(Boolean, default=False)
    poc_steps = Column(JSONB)
    mitre_tactics = Column(JSONB)  # Array stored as JSONB
    aws_services = Column(JSONB)  # Array stored as JSONB
    # PoC Validation fields (v2)
    validation_status = Column(String(32), default="pending")
    validation_timestamp = Column(DateTime)
    validation_evidence = Column(JSONB)
    validation_error = Column(Text)
    # Runtime correlation fields (v2)
    runtime_confirmed = Column(Boolean, default=False)
    cloudtrail_events = Column(JSONB, default=[])
    # Confidence scoring fields (Tier 1)
    confidence_score = Column(Integer, default=0)  # 0-100 confidence score
    confidence_factors = Column(JSONB, default={})  # Breakdown of score factors
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan")


# ============================================================================
# Pentest Feature Models
# ============================================================================


class PublicExposure(Base):
    """Public exposure aggregator model."""

    __tablename__ = "public_exposures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    exposure_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    cloud_provider = Column(String(32))
    account_id = Column(String(128))
    region = Column(String(64))
    resource_type = Column(String(128))
    resource_id = Column(String(512))
    resource_name = Column(String(512))
    exposure_type = Column(String(64))
    exposure_details = Column(JSONB)
    risk_level = Column(String(16), default="medium")
    protocol = Column(String(32))
    port_range = Column(String(64))
    source_cidr = Column(String(64))
    is_internet_exposed = Column(Boolean, default=False)
    finding_ids = Column(JSONB)
    tags = Column(JSONB)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(32), default="open")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ExposedCredential(Base):
    """Exposed credential model for credential harvesting."""

    __tablename__ = "exposed_credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    credential_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    cloud_provider = Column(String(32))
    account_id = Column(String(128))
    region = Column(String(64))
    source_type = Column(String(64))
    source_location = Column(String(512))
    credential_type = Column(String(64))
    credential_name = Column(String(256))
    exposed_value_hash = Column(String(128))
    is_active = Column(Boolean, default=True)
    risk_level = Column(String(16), default="critical")
    finding_ids = Column(JSONB)
    discovered_by = Column(String(64))
    remediation_status = Column(String(32), default="pending")
    remediation_notes = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SeverityOverride(Base):
    """Severity override model for finding severity adjustments."""

    __tablename__ = "severity_overrides"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), unique=True)
    original_severity = Column(String(16))
    new_severity = Column(String(16))
    justification = Column(Text)
    override_type = Column(String(32), default="manual")
    created_by = Column(String(128))
    approved_by = Column(String(128))
    approval_status = Column(String(32), default="pending")
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    finding = relationship("Finding")


class PrivescPath(Base):
    """Privilege escalation path model."""

    __tablename__ = "privesc_paths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    path_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    cloud_provider = Column(String(32))
    account_id = Column(String(128))
    source_principal_type = Column(String(64))
    source_principal_arn = Column(String(512))
    source_principal_name = Column(String(256))
    target_principal_type = Column(String(64))
    target_principal_arn = Column(String(512))
    target_principal_name = Column(String(256))
    escalation_method = Column(String(128))
    escalation_details = Column(JSONB)
    path_nodes = Column(JSONB)
    path_edges = Column(JSONB)
    risk_score = Column(Integer, default=0)
    exploitability = Column(String(32), default="theoretical")
    requires_conditions = Column(JSONB)
    mitre_techniques = Column(JSONB)
    poc_commands = Column(JSONB)
    finding_ids = Column(JSONB)
    status = Column(String(32), default="open")
    # PoC Validation fields (v2)
    validation_status = Column(String(32), default="pending")
    validation_timestamp = Column(DateTime)
    validation_evidence = Column(JSONB)
    # Runtime correlation fields (v2)
    runtime_confirmed = Column(Boolean, default=False)
    cloudtrail_events = Column(JSONB, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ImdsCheck(Base):
    """IMDS/Metadata checker model."""

    __tablename__ = "imds_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    check_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    cloud_provider = Column(String(32))
    account_id = Column(String(128))
    region = Column(String(64))
    instance_id = Column(String(128))
    instance_name = Column(String(256))
    imds_version = Column(String(16))
    imds_v1_enabled = Column(Boolean, default=False)
    imds_hop_limit = Column(Integer)
    http_endpoint_enabled = Column(Boolean, default=True)
    http_tokens_required = Column(Boolean, default=False)
    ssrf_vulnerable = Column(Boolean, default=False)
    container_credential_exposure = Column(Boolean, default=False)
    ecs_task_role_exposed = Column(Boolean, default=False)
    eks_pod_identity_exposed = Column(Boolean, default=False)
    vulnerability_details = Column(JSONB)
    risk_level = Column(String(16), default="medium")
    finding_ids = Column(JSONB)
    remediation_status = Column(String(32), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CloudfoxResult(Base):
    """CloudFox enumeration result model."""

    __tablename__ = "cloudfox_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    result_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    cloud_provider = Column(String(32))
    account_id = Column(String(128))
    region = Column(String(64))
    module_name = Column(String(64))
    result_type = Column(String(64))
    resource_arn = Column(String(512))
    resource_name = Column(String(256))
    finding_category = Column(String(64))
    finding_details = Column(JSONB)
    risk_level = Column(String(16), default="medium")
    loot_file_path = Column(String(512))
    raw_output = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PacuResult(Base):
    """Pacu module execution result model."""

    __tablename__ = "pacu_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    result_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    session_name = Column(String(128))
    module_name = Column(String(128))
    module_category = Column(String(64))
    execution_status = Column(String(32))
    target_account_id = Column(String(128))
    target_region = Column(String(64))
    resources_affected = Column(Integer, default=0)
    permissions_used = Column(JSONB)
    findings = Column(JSONB)
    loot_data = Column(JSONB)
    error_message = Column(Text)
    execution_time_ms = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EnumerateIamResult(Base):
    """enumerate-iam result model."""

    __tablename__ = "enumerate_iam_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    result_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    account_id = Column(String(128))
    principal_arn = Column(String(512))
    principal_name = Column(String(256))
    principal_type = Column(String(64))
    enumeration_method = Column(String(64))
    confirmed_permissions = Column(JSONB)
    denied_permissions = Column(JSONB)
    error_permissions = Column(JSONB)
    permission_count = Column(Integer, default=0)
    high_risk_permissions = Column(JSONB)
    privesc_capable = Column(Boolean, default=False)
    data_access_capable = Column(Boolean, default=False)
    admin_capable = Column(Boolean, default=False)
    enumeration_duration_ms = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AssumedRoleMapping(Base):
    """Assumed role mapping model for Neo4j visualization."""

    __tablename__ = "assumed_role_mappings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mapping_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    cloud_provider = Column(String(32))
    account_id = Column(String(128))
    source_principal_type = Column(String(64))
    source_principal_arn = Column(String(512))
    source_principal_name = Column(String(256))
    source_account_id = Column(String(128))
    target_role_arn = Column(String(512))
    target_role_name = Column(String(256))
    target_account_id = Column(String(128))
    trust_policy = Column(JSONB)
    conditions = Column(JSONB)
    is_cross_account = Column(Boolean, default=False)
    is_external_id_required = Column(Boolean, default=False)
    external_id_value = Column(String(256))
    max_session_duration = Column(Integer)
    assumption_chain_depth = Column(Integer, default=1)
    risk_level = Column(String(16), default="medium")
    neo4j_synced = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LambdaAnalysis(Base):
    """Lambda code analysis result model."""

    __tablename__ = "lambda_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(64), unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    cloud_provider = Column(String(32), default="aws")
    account_id = Column(String(128))
    region = Column(String(64))
    function_arn = Column(String(512))
    function_name = Column(String(256))
    runtime = Column(String(64))
    handler = Column(String(256))
    code_size_bytes = Column(Integer)
    memory_size = Column(Integer)
    timeout_seconds = Column(Integer)
    environment_variables = Column(JSONB)
    has_vpc_config = Column(Boolean, default=False)
    layers = Column(JSONB)
    secrets_found = Column(JSONB)
    hardcoded_credentials = Column(JSONB)
    vulnerable_dependencies = Column(JSONB)
    insecure_patterns = Column(JSONB)
    api_keys_exposed = Column(JSONB)
    database_connections = Column(JSONB)
    external_urls = Column(JSONB)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(16), default="medium")
    finding_ids = Column(JSONB)
    analysis_status = Column(String(32), default="pending")
    analysis_error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ToolExecution(Base):
    """Tool execution tracking model for async container runs."""

    __tablename__ = "tool_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    execution_id = Column(String(64), unique=True)
    tool_name = Column(String(64))
    tool_type = Column(String(32))
    status = Column(String(32), default="pending")
    container_id = Column(String(128))
    config = Column(JSONB, default={})
    output_path = Column(String(512))
    error_message = Column(Text)
    exit_code = Column(Integer)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UserSetting(Base):
    """User settings model for application preferences."""

    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    setting_key = Column(String(128), unique=True, nullable=False)
    setting_value = Column(JSONB, nullable=False)
    category = Column(String(64), nullable=False)
    description = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanSchedule(Base):
    """Scan schedule model for scheduled/recurring scans."""

    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    schedule_id = Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4)
    name = Column(String(128), nullable=False)
    description = Column(Text)
    profile = Column(String(64), nullable=False)
    provider = Column(String(32))
    aws_profile = Column(String(64))
    azure_credentials = Column(JSONB)
    schedule_type = Column(String(32), nullable=False, default="cron")
    cron_expression = Column(String(128))
    interval_minutes = Column(Integer)
    next_run_at = Column(DateTime)
    last_run_at = Column(DateTime)
    last_run_status = Column(String(32))
    last_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="SET NULL"))
    is_enabled = Column(Boolean, default=True)
    run_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    last_error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    last_scan = relationship("Scan", foreign_keys=[last_scan_id])


class CredentialStatusCache(Base):
    """Credential status cache for quick status display."""

    __tablename__ = "credential_status_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    provider = Column(String(32), unique=True, nullable=False)
    status = Column(String(32), nullable=False, default="unknown")
    identity = Column(String(256))
    account_info = Column(String(256))
    tools_ready = Column(JSONB, default=[])
    tools_partial = Column(JSONB, default=[])
    tools_failed = Column(JSONB, default=[])
    last_verified = Column(DateTime)
    verification_error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================================================
# Attack Path Validation Models (v2)
# ============================================================================


class BlastRadiusAnalysis(Base):
    """Blast radius analysis model for identity impact calculation."""

    __tablename__ = "blast_radius_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(64), unique=True, nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"))
    identity_arn = Column(String(512), nullable=False)
    identity_type = Column(String(64))
    account_id = Column(String(128))
    # Direct permissions
    direct_permission_count = Column(Integer, default=0)
    direct_resource_count = Column(Integer, default=0)
    # Role assumption analysis
    assumable_roles_count = Column(Integer, default=0)
    assumption_chain_depth = Column(Integer, default=1)
    cross_account_roles_count = Column(Integer, default=0)
    affected_accounts = Column(JSONB, default=[])
    # Calculated blast radius
    total_blast_radius = Column(Integer, default=0)
    risk_level = Column(String(16), default="medium")
    # Detailed breakdown
    reachable_resources = Column(JSONB)
    reachable_roles = Column(JSONB)
    permission_breakdown = Column(JSONB)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan")


class RuntimeCorrelation(Base):
    """Runtime correlation model for CloudTrail event matching."""

    __tablename__ = "runtime_correlations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    correlation_id = Column(String(64), unique=True, nullable=False)
    # References (one will be set)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"))
    attack_path_id = Column(Integer, ForeignKey("attack_paths.id", ondelete="CASCADE"))
    privesc_path_id = Column(Integer, ForeignKey("privesc_paths.id", ondelete="CASCADE"))
    # CloudTrail event details
    event_id = Column(String(128))
    event_source = Column(String(128))
    event_name = Column(String(128))
    event_time = Column(DateTime)
    source_ip = Column(String(64))
    user_identity = Column(JSONB)
    request_parameters = Column(JSONB)
    response_elements = Column(JSONB)
    # Correlation analysis
    correlation_type = Column(String(64))
    confidence_score = Column(Integer, default=0)
    analysis_notes = Column(Text)
    confirms_exploitability = Column(Boolean, default=False)
    anomaly_detected = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    finding = relationship("Finding")
    attack_path = relationship("AttackPath")
    privesc_path = relationship("PrivescPath")


# ============================================================================
# Risk Exception & Analysis Job Models (Tier 1 & 2)
# ============================================================================


class RiskException(Base):
    """Risk exception model for compliance exception tracking."""

    __tablename__ = "risk_exceptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    exception_id = Column(String(64), unique=True, nullable=False)
    canonical_id = Column(String(256), nullable=False)  # Cross-scan persistence
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"))
    justification = Column(Text, nullable=False)
    expiration_date = Column(DateTime)  # Optional: null = permanent exception
    accepted_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(32), default="active")  # active, expired, revoked
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    finding = relationship("Finding")


class AnalysisJob(Base):
    """Analysis job model for async attack path analysis."""

    __tablename__ = "analysis_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), unique=True, nullable=False)
    job_type = Column(String(32), nullable=False)  # attack_path, privesc, blast_radius
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="SET NULL"))
    status = Column(String(32), default="pending")  # pending, running, completed, failed
    progress = Column(Integer, default=0)  # 0-100 percent
    result_summary = Column(JSONB)
    error_message = Column(Text)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan = relationship("Scan")


class FindingValidation(Base):
    """Finding validation model for individual finding PoC validation."""

    __tablename__ = "finding_validations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    validation_id = Column(String(64), unique=True, nullable=False)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    validation_status = Column(String(32), default="pending")  # pending, validated, blocked, failed
    validation_timestamp = Column(DateTime)
    evidence = Column(JSONB, default=[])  # List of validation evidence
    error_message = Column(Text)
    dry_run = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    finding = relationship("Finding")
