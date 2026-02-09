"""Tests for export endpoints."""

from datetime import datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from models.database import Finding, Scan


class TestCSVExport:
    """Test cases for CSV export."""

    def test_export_csv_empty(self, client: TestClient) -> None:
        """Test CSV export with no findings."""
        response = client.get("/api/exports/csv")

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        assert "Content-Disposition" in response.headers
        assert "findings_export_" in response.headers["Content-Disposition"]

    def test_export_csv_with_data(self, client: TestClient, sample_findings) -> None:
        """Test CSV export includes findings data."""
        response = client.get("/api/exports/csv")

        assert response.status_code == 200
        content = response.text
        # Check header row exists
        assert "finding_id" in content
        assert "severity" in content
        assert "title" in content

    def test_export_csv_filter_by_severity(self, client: TestClient, sample_findings) -> None:
        """Test CSV export with severity filter."""
        response = client.get("/api/exports/csv?severity=critical")

        assert response.status_code == 200
        content = response.text
        lines = content.strip().split("\n")
        # Header + data rows (only critical)
        assert len(lines) >= 1

    def test_export_csv_filter_by_status(self, client: TestClient, sample_findings) -> None:
        """Test CSV export with status filter."""
        response = client.get("/api/exports/csv?status=open")

        assert response.status_code == 200

    def test_export_csv_include_remediation(self, client: TestClient, sample_findings) -> None:
        """Test CSV export includes remediation column."""
        response = client.get("/api/exports/csv?include_remediation=true")

        assert response.status_code == 200
        content = response.text
        assert "remediation" in content.split("\n")[0]

    def test_export_csv_exclude_remediation(self, client: TestClient, sample_findings) -> None:
        """Test CSV export excludes remediation when disabled."""
        response = client.get("/api/exports/csv?include_remediation=false")

        assert response.status_code == 200
        content = response.text
        # Remediation should not be in header
        headers = content.split("\n")[0]
        assert "remediation" not in headers


class TestJSONExport:
    """Test cases for JSON export."""

    def test_export_json_empty(self, client: TestClient) -> None:
        """Test JSON export with no findings."""
        response = client.get("/api/exports/json")

        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]

        data = response.json()
        assert "findings" in data
        assert data["findings"] == []
        assert data["total_findings"] == 0

    def test_export_json_with_data(self, client: TestClient, sample_findings) -> None:
        """Test JSON export includes findings data."""
        response = client.get("/api/exports/json")

        assert response.status_code == 200
        data = response.json()
        assert data["total_findings"] > 0
        assert "export_timestamp" in data
        assert "filters" in data

    def test_export_json_filter_by_severity(self, client: TestClient, sample_findings) -> None:
        """Test JSON export with severity filter."""
        response = client.get("/api/exports/json?severity=high")

        assert response.status_code == 200
        data = response.json()
        assert data["filters"]["severity"] == "high"
        assert all(f["severity"] == "high" for f in data["findings"])

    def test_export_json_filter_by_cloud_provider(
        self, client: TestClient, sample_findings
    ) -> None:
        """Test JSON export with cloud provider filter."""
        response = client.get("/api/exports/json?cloud_provider=aws")

        assert response.status_code == 200
        data = response.json()
        assert data["filters"]["cloud_provider"] == "aws"

    def test_export_json_finding_structure(self, client: TestClient, sample_finding) -> None:
        """Test JSON export finding has correct structure."""
        response = client.get("/api/exports/json?status=open")

        assert response.status_code == 200
        data = response.json()
        if data["findings"]:
            finding = data["findings"][0]
            required_fields = [
                "finding_id",
                "tool",
                "severity",
                "status",
                "title",
                "description",
                "resource_type",
            ]
            for field in required_fields:
                assert field in finding


class TestGenerateExport:
    """Test cases for generate export endpoint."""

    def test_generate_export_default(self, client: TestClient) -> None:
        """Test generating export with default options."""
        response = client.post("/api/exports/generate", json={})

        assert response.status_code == 200
        data = response.json()
        assert "export_id" in data
        assert "filename" in data
        assert "format" in data
        assert "record_count" in data
        assert "download_url" in data
        assert "generated_at" in data

    def test_generate_export_csv_format(self, client: TestClient, sample_findings) -> None:
        """Test generating CSV export."""
        response = client.post("/api/exports/generate", json={"format": "csv"})

        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "csv"
        assert ".csv" in data["filename"]

    def test_generate_export_json_format(self, client: TestClient, sample_findings) -> None:
        """Test generating JSON export."""
        response = client.post("/api/exports/generate", json={"format": "json"})

        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "json"
        assert ".json" in data["filename"]

    def test_generate_export_with_severity_filter(
        self, client: TestClient, sample_findings
    ) -> None:
        """Test generating export with severity filter."""
        response = client.post(
            "/api/exports/generate", json={"severity_filter": ["critical", "high"]}
        )

        assert response.status_code == 200

    def test_generate_export_with_status_filter(self, client: TestClient, sample_findings) -> None:
        """Test generating export with status filter."""
        response = client.post("/api/exports/generate", json={"status_filter": ["open"]})

        assert response.status_code == 200


class TestExportSummary:
    """Test cases for export summary endpoint."""

    def test_export_summary_empty(self, client: TestClient) -> None:
        """Test export summary with no findings."""
        response = client.get("/api/exports/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_open_findings"] == 0
        assert "generated_at" in data
        assert "by_severity" in data
        assert "by_provider" in data
        assert "by_tool" in data

    def test_export_summary_with_data(self, client: TestClient, sample_findings) -> None:
        """Test export summary with findings data."""
        response = client.get("/api/exports/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_open_findings"] >= 0
        assert isinstance(data["by_severity"], dict)
        assert isinstance(data["by_provider"], dict)
        assert isinstance(data["by_tool"], dict)


class TestJSONExportSource:
    """Test export_source field in JSON export."""

    def test_export_json_has_export_source(self, client: TestClient) -> None:
        """Test JSON export includes export_source field."""
        response = client.get("/api/exports/json")

        assert response.status_code == 200
        data = response.json()
        assert data["export_source"] == "nubicustos"


class TestContainerExport:
    """Test cases for container export endpoint."""

    def test_export_containers_empty(self, client: TestClient) -> None:
        """Test container export with no findings."""
        response = client.get("/api/exports/containers")

        assert response.status_code == 200
        data = response.json()
        assert data["containers"] == []
        assert data["total_containers"] == 0

    def test_export_containers_with_data(
        self, client: TestClient, db_session: Session, sample_scan: Scan
    ) -> None:
        """Test container export includes container findings."""
        # Create container-related findings
        container_finding = Finding(
            finding_id=f"finding-{uuid4().hex[:8]}",
            scan_id=sample_scan.scan_id,
            tool="prowler",
            cloud_provider="aws",
            severity="high",
            status="open",
            title="ECS Container Misconfiguration",
            description="Container running as root",
            resource_type="ECS::Container",
            resource_id="ecs-container-001",
            resource_name="web-app-container",
            region="us-east-1",
            account_id="123456789012",
            scan_date=datetime.utcnow(),
            finding_metadata={
                "container_image": "nginx:latest",
                "runtime": "docker",
                "privileged": True,
                "namespace": "production",
            },
        )
        db_session.add(container_finding)
        db_session.commit()

        response = client.get("/api/exports/containers")

        assert response.status_code == 200
        data = response.json()
        assert data["total_containers"] == 1
        assert len(data["containers"]) == 1

        container = data["containers"][0]
        assert container["resource_id"] == "ecs-container-001"
        assert container["resource_name"] == "web-app-container"
        assert container["resource_type"] == "ECS::Container"
        assert container["cloud_provider"] == "aws"
        assert container["region"] == "us-east-1"
        assert container["account_id"] == "123456789012"
        assert container["container_image"] == "nginx:latest"
        assert container["runtime"] == "docker"
        assert container["privileged"] is True
        assert container["namespace"] == "production"

    def test_export_containers_has_export_source(self, client: TestClient) -> None:
        """Test container export includes export_source field."""
        response = client.get("/api/exports/containers")

        assert response.status_code == 200
        data = response.json()
        assert data["export_source"] == "nubicustos"
        assert "export_timestamp" in data
        assert "filters" in data

    def test_export_containers_filter_by_cloud_provider(
        self, client: TestClient, db_session: Session, sample_scan: Scan
    ) -> None:
        """Test container export filters by cloud provider."""
        # Create findings for different providers
        for provider, rid in [("aws", "ecs-001"), ("gcp", "gke-001")]:
            finding = Finding(
                finding_id=f"finding-{uuid4().hex[:8]}",
                scan_id=sample_scan.scan_id,
                tool="prowler",
                cloud_provider=provider,
                severity="high",
                status="open",
                title=f"Container issue ({provider})",
                description="Container misconfiguration",
                resource_type="ECS::Container" if provider == "aws" else "GKE::Container",
                resource_id=rid,
                resource_name=f"container-{provider}",
                region="us-east-1",
                account_id="123456789012",
                scan_date=datetime.utcnow(),
            )
            db_session.add(finding)
        db_session.commit()

        # Filter to AWS only
        response = client.get("/api/exports/containers?cloud_provider=aws")

        assert response.status_code == 200
        data = response.json()
        assert data["total_containers"] == 1
        assert data["containers"][0]["cloud_provider"] == "aws"
        assert data["filters"]["cloud_provider"] == "aws"
