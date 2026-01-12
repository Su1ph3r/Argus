"""Tests for scans endpoints."""

from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


class TestListScans:
    """Test cases for listing scans."""

    def test_list_scans_empty(self, client: TestClient) -> None:
        """Test listing scans when none exist."""
        response = client.get("/api/scans")

        assert response.status_code == 200
        data = response.json()
        assert data["scans"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["page_size"] == 20

    def test_list_scans_with_data(self, client: TestClient, sample_scan) -> None:
        """Test listing scans returns existing scans."""
        response = client.get("/api/scans")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["scans"]) == 1
        assert data["scans"][0]["scan_id"] == str(sample_scan.scan_id)

    def test_list_scans_with_trailing_slash(self, client: TestClient) -> None:
        """Test listing scans with trailing slash works."""
        response = client.get("/api/scans/")

        assert response.status_code == 200

    def test_list_scans_pagination(self, client: TestClient, sample_scan) -> None:
        """Test scan listing pagination parameters."""
        response = client.get("/api/scans?page=1&page_size=10")

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 10

    def test_list_scans_filter_by_status(self, client: TestClient, sample_scan) -> None:
        """Test filtering scans by status."""
        response = client.get("/api/scans?status=completed")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1

        response = client.get("/api/scans?status=running")
        data = response.json()
        assert data["total"] == 0

    def test_list_scans_filter_by_tool(self, client: TestClient, sample_scan) -> None:
        """Test filtering scans by tool."""
        response = client.get("/api/scans?tool=multi-tool")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1


class TestCreateScan:
    """Test cases for creating scans."""

    def test_create_scan_default_profile(self, client: TestClient) -> None:
        """Test creating a scan with default profile."""
        response = client.post("/api/scans", json={"dry_run": True})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending"
        assert "scan_id" in data

    def test_create_scan_with_profile(self, client: TestClient) -> None:
        """Test creating a scan with specific profile."""
        response = client.post("/api/scans", json={"profile": "quick", "dry_run": True})

        assert response.status_code == 200
        data = response.json()
        assert data["scan_type"] == "quick"

    def test_create_scan_with_severity_filter(self, client: TestClient) -> None:
        """Test creating a scan with severity filter."""
        response = client.post(
            "/api/scans",
            json={"profile": "quick", "severity_filter": "critical,high", "dry_run": True},
        )

        assert response.status_code == 200

    def test_create_scan_with_target(self, client: TestClient) -> None:
        """Test creating a scan with specific target."""
        response = client.post("/api/scans", json={"target": "aws-account-123", "dry_run": True})

        assert response.status_code == 200
        data = response.json()
        assert data["target"] == "aws-account-123"


class TestGetScan:
    """Test cases for getting individual scans."""

    def test_get_scan_by_id(self, client: TestClient, sample_scan) -> None:
        """Test getting a scan by its ID."""
        response = client.get(f"/api/scans/{sample_scan.scan_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == str(sample_scan.scan_id)
        assert data["status"] == sample_scan.status

    def test_get_scan_not_found(self, client: TestClient) -> None:
        """Test getting a non-existent scan returns 404."""
        fake_id = uuid4()
        response = client.get(f"/api/scans/{fake_id}")

        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"

    def test_get_scan_status(self, client: TestClient, sample_scan) -> None:
        """Test getting scan status."""
        response = client.get(f"/api/scans/{sample_scan.scan_id}/status")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == str(sample_scan.scan_id)
        assert data["status"] == "completed"
        assert "findings" in data

    def test_get_scan_status_not_found(self, client: TestClient) -> None:
        """Test getting status of non-existent scan returns 404."""
        fake_id = uuid4()
        response = client.get(f"/api/scans/{fake_id}/status")

        assert response.status_code == 404


class TestCancelScan:
    """Test cases for cancelling scans."""

    def test_cancel_running_scan(self, client: TestClient, db_session: Session) -> None:
        """Test cancelling a running scan."""
        from datetime import datetime

        from models.database import Scan

        scan = Scan(
            scan_id=uuid4(),
            status="running",
            started_at=datetime.utcnow(),
        )
        db_session.add(scan)
        db_session.commit()

        response = client.delete(f"/api/scans/{scan.scan_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Scan cancelled"

    def test_cancel_completed_scan_fails(self, client: TestClient, sample_scan) -> None:
        """Test cancelling a completed scan returns error."""
        response = client.delete(f"/api/scans/{sample_scan.scan_id}")

        assert response.status_code == 400
        assert "Cannot cancel" in response.json()["detail"]

    def test_cancel_nonexistent_scan(self, client: TestClient) -> None:
        """Test cancelling a non-existent scan returns 404."""
        fake_id = uuid4()
        response = client.delete(f"/api/scans/{fake_id}")

        assert response.status_code == 404


class TestListProfiles:
    """Test cases for listing scan profiles."""

    def test_list_profiles(self, client: TestClient) -> None:
        """Test listing available scan profiles."""
        response = client.get("/api/scans/profiles/list")

        assert response.status_code == 200
        data = response.json()
        assert "profiles" in data
        assert len(data["profiles"]) == 3

        profile_names = [p["name"] for p in data["profiles"]]
        assert "quick" in profile_names
        assert "comprehensive" in profile_names
        assert "compliance-only" in profile_names

    def test_profile_has_required_fields(self, client: TestClient) -> None:
        """Test each profile has required fields."""
        response = client.get("/api/scans/profiles/list")

        data = response.json()
        for profile in data["profiles"]:
            assert "name" in profile
            assert "description" in profile
            assert "duration_estimate" in profile
