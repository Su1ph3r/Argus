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
    raw_data = Column(JSONB)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    scan_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
