"""Database connection and SQLAlchemy models."""
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean, Numeric, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import uuid

from config import get_settings

settings = get_settings()

# Create engine
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

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
    aws_services = Column(JSONB)   # Array stored as JSONB
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan")
