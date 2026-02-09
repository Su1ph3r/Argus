"""Pytest fixtures for API tests."""

import sys
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import JSON, String, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Patch PostgreSQL JSONB to use generic JSON before any models load.
# This must happen before `from models.database import ...` which uses
# `from sqlalchemy.dialects.postgresql import JSONB`.
# We replace the class in the module so future `from ... import JSONB` gets JSON.
import sqlalchemy.dialects.postgresql as _pg_mod
import sqlalchemy.dialects.postgresql.json as _pg_json_mod

_OrigJSONB = _pg_mod.JSONB
_pg_mod.JSONB = JSON
_pg_json_mod.JSONB = JSON

# Similarly patch UUID to work with SQLite (renders as VARCHAR)
_OrigUUID = _pg_mod.UUID
_pg_mod.UUID = lambda *a, **kw: String(36)

# Register UUID adapter for SQLite so it can bind uuid.UUID objects
import sqlite3
import uuid as _uuid_mod

sqlite3.register_adapter(_uuid_mod.UUID, str)

# Ensure the api directory is in the path for imports
api_dir = Path(__file__).parent.parent
if str(api_dir) not in sys.path:
    sys.path.insert(0, str(api_dir))

from main import app
from models.database import AttackPath, Base, Finding, Scan, get_db

# Create in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Create a fresh database session for each test."""
    # Create all tables
    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        # Drop all tables after test
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Create a test client with overridden database dependency."""

    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def sample_scan(db_session: Session) -> Scan:
    """Create a sample scan for testing."""
    scan = Scan(
        scan_id=uuid4(),
        scan_type="comprehensive",
        target="all",
        tool="multi-tool",
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        total_findings=5,
        critical_findings=1,
        high_findings=2,
        medium_findings=1,
        low_findings=1,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


@pytest.fixture
def sample_finding(db_session: Session, sample_scan: Scan) -> Finding:
    """Create a sample finding for testing."""
    finding = Finding(
        finding_id=f"finding-{uuid4().hex[:8]}",
        scan_id=sample_scan.scan_id,
        tool="prowler",
        cloud_provider="aws",
        severity="high",
        status="open",
        title="Test Finding",
        description="This is a test finding for unit tests.",
        remediation="Apply the recommended fix.",
        resource_type="EC2::Instance",
        resource_id="i-1234567890abcdef0",
        resource_name="test-instance",
        region="us-east-1",
        account_id="123456789012",
        scan_date=datetime.utcnow(),
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


@pytest.fixture
def sample_findings(db_session: Session, sample_scan: Scan) -> list[Finding]:
    """Create multiple sample findings for testing."""
    findings = []
    severities = ["critical", "high", "high", "medium", "low"]

    for i, severity in enumerate(severities):
        finding = Finding(
            finding_id=f"finding-{uuid4().hex[:8]}",
            scan_id=sample_scan.scan_id,
            tool="prowler" if i % 2 == 0 else "scoutsuite",
            cloud_provider="aws" if i % 3 == 0 else "gcp",
            severity=severity,
            status="open" if i < 4 else "closed",
            title=f"Test Finding {i+1}",
            description=f"Description for finding {i+1}",
            remediation=f"Remediation for finding {i+1}",
            resource_type="EC2::Instance" if i % 2 == 0 else "S3::Bucket",
            resource_id=f"resource-{i}",
            resource_name=f"test-resource-{i}",
            region="us-east-1",
            account_id="123456789012",
            scan_date=datetime.utcnow(),
        )
        findings.append(finding)
        db_session.add(finding)

    db_session.commit()
    for f in findings:
        db_session.refresh(f)

    return findings


@pytest.fixture
def sample_attack_path(db_session: Session, sample_scan: Scan) -> AttackPath:
    """Create a sample attack path for testing."""
    attack_path = AttackPath(
        path_id=f"path-{uuid4().hex[:8]}",
        scan_id=sample_scan.scan_id,
        name="Public S3 to IAM Escalation",
        description="Attack path from public S3 bucket to IAM privilege escalation",
        entry_point_type="public_s3",
        entry_point_id="arn:aws:s3:::test-bucket",
        entry_point_name="test-bucket",
        target_type="iam_admin",
        target_description="IAM administrative access",
        nodes=[
            {"id": "n1", "type": "entry_point", "name": "Public S3", "resource_id": "test-bucket"},
            {"id": "n2", "type": "resource", "name": "Lambda Function", "resource_id": "func-1"},
            {"id": "n3", "type": "target", "name": "IAM Admin", "resource_id": None},
        ],
        edges=[
            {"id": "e1", "source": "n1", "target": "n2", "type": "access", "name": "S3 trigger"},
            {
                "id": "e2",
                "source": "n2",
                "target": "n3",
                "type": "privilege",
                "name": "IAM escalation",
            },
        ],
        finding_ids=[],
        risk_score=85,
        exploitability="confirmed",
        impact="critical",
        hop_count=2,
        requires_authentication=False,
        requires_privileges=False,
        poc_available=True,
        poc_steps=[
            {
                "step": 1,
                "name": "Access S3",
                "description": "Access public bucket",
                "command": "aws s3 ls s3://test-bucket",
            }
        ],
        mitre_tactics=["Initial Access", "Privilege Escalation"],
        aws_services=["S3", "Lambda", "IAM"],
    )
    db_session.add(attack_path)
    db_session.commit()
    db_session.refresh(attack_path)
    return attack_path
