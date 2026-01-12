"""Tests for findings endpoints."""

from fastapi.testclient import TestClient


class TestListFindings:
    """Test cases for listing findings."""

    def test_list_findings_empty(self, client: TestClient) -> None:
        """Test listing findings when none exist."""
        response = client.get("/api/findings")

        assert response.status_code == 200
        data = response.json()
        assert data["findings"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["page_size"] == 50

    def test_list_findings_with_data(self, client: TestClient, sample_findings) -> None:
        """Test listing findings returns existing findings."""
        response = client.get("/api/findings")

        assert response.status_code == 200
        data = response.json()
        # Default filter is open+fail status, so closed findings are excluded
        assert data["total"] == 4  # 4 open, 1 closed

    def test_list_findings_with_trailing_slash(self, client: TestClient) -> None:
        """Test listing findings with trailing slash works."""
        response = client.get("/api/findings/")

        assert response.status_code == 200

    def test_list_findings_pagination(self, client: TestClient, sample_findings) -> None:
        """Test findings pagination parameters."""
        response = client.get("/api/findings?page=1&page_size=2")

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 2
        assert len(data["findings"]) <= 2


class TestFindingsFilters:
    """Test cases for findings filtering."""

    def test_filter_by_severity(self, client: TestClient, sample_findings) -> None:
        """Test filtering findings by severity."""
        response = client.get("/api/findings?severity=critical")

        assert response.status_code == 200
        data = response.json()
        assert all(f["severity"] == "critical" for f in data["findings"])

    def test_filter_by_multiple_severities(self, client: TestClient, sample_findings) -> None:
        """Test filtering by multiple severities."""
        response = client.get("/api/findings?severity=critical,high")

        assert response.status_code == 200
        data = response.json()
        assert all(f["severity"] in ["critical", "high"] for f in data["findings"])

    def test_filter_by_status(self, client: TestClient, sample_findings) -> None:
        """Test filtering findings by status."""
        response = client.get("/api/findings?status=closed")

        assert response.status_code == 200
        data = response.json()
        assert all(f["status"] == "closed" for f in data["findings"])

    def test_filter_by_cloud_provider(self, client: TestClient, sample_findings) -> None:
        """Test filtering by cloud provider."""
        response = client.get("/api/findings?cloud_provider=aws")

        assert response.status_code == 200
        data = response.json()
        assert all(f["cloud_provider"] == "aws" for f in data["findings"])

    def test_filter_by_tool(self, client: TestClient, sample_findings) -> None:
        """Test filtering by scanning tool."""
        response = client.get("/api/findings?tool=prowler")

        assert response.status_code == 200
        data = response.json()
        assert all(f["tool"] == "prowler" for f in data["findings"])

    def test_filter_by_resource_type(self, client: TestClient, sample_findings) -> None:
        """Test filtering by resource type."""
        response = client.get("/api/findings?resource_type=EC2::Instance")

        assert response.status_code == 200
        data = response.json()
        assert all(f["resource_type"] == "EC2::Instance" for f in data["findings"])

    def test_search_by_title(self, client: TestClient, sample_findings) -> None:
        """Test searching findings by title."""
        response = client.get("/api/findings?search=Finding%201")

        assert response.status_code == 200
        data = response.json()
        assert len(data["findings"]) >= 1

    def test_search_escapes_wildcards(self, client: TestClient, sample_findings) -> None:
        """Test search properly escapes SQL wildcards."""
        # This should not match everything
        response = client.get("/api/findings?search=%25")

        assert response.status_code == 200
        data = response.json()
        # Should not match anything since % is escaped
        assert data["total"] == 0


class TestGetFinding:
    """Test cases for getting individual findings."""

    def test_get_finding_by_id(self, client: TestClient, sample_finding) -> None:
        """Test getting a finding by its ID."""
        response = client.get(f"/api/findings/{sample_finding.id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == sample_finding.id
        assert data["title"] == sample_finding.title

    def test_get_finding_not_found(self, client: TestClient) -> None:
        """Test getting a non-existent finding returns 404."""
        response = client.get("/api/findings/99999")

        assert response.status_code == 404
        assert response.json()["detail"] == "Finding not found"

    def test_get_finding_includes_aggregated_data(self, client: TestClient, sample_finding) -> None:
        """Test finding response includes tool_sources and affected_resources."""
        response = client.get(f"/api/findings/{sample_finding.id}")

        assert response.status_code == 200
        data = response.json()
        assert "tool_sources" in data
        assert "affected_resources" in data
        assert "affected_count" in data


class TestUpdateFinding:
    """Test cases for updating findings."""

    def test_update_finding_status(self, client: TestClient, sample_finding) -> None:
        """Test updating a finding's status."""
        response = client.patch(f"/api/findings/{sample_finding.id}", json={"status": "mitigated"})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "mitigated"

    def test_update_finding_tags(self, client: TestClient, sample_finding) -> None:
        """Test updating a finding's tags."""
        response = client.patch(
            f"/api/findings/{sample_finding.id}",
            json={"tags": {"priority": "urgent", "team": "security"}},
        )

        assert response.status_code == 200

    def test_update_finding_not_found(self, client: TestClient) -> None:
        """Test updating a non-existent finding returns 404."""
        response = client.patch("/api/findings/99999", json={"status": "closed"})

        assert response.status_code == 404


class TestFindingsSummary:
    """Test cases for findings summary endpoint."""

    def test_get_summary_empty(self, client: TestClient) -> None:
        """Test summary with no findings."""
        response = client.get("/api/findings/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["critical"] == 0
        assert data["high"] == 0

    def test_get_summary_with_data(self, client: TestClient, sample_findings) -> None:
        """Test summary returns correct counts."""
        response = client.get("/api/findings/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] > 0
        assert "by_provider" in data
        assert "by_tool" in data

    def test_summary_filter_by_status(self, client: TestClient, sample_findings) -> None:
        """Test summary respects status filter."""
        response = client.get("/api/findings/summary?status=closed")

        assert response.status_code == 200
        data = response.json()
        # Only closed findings should be counted
        assert data["total"] == 1


class TestFindingsByResource:
    """Test cases for getting findings by resource."""

    def test_get_findings_by_resource(self, client: TestClient, sample_finding) -> None:
        """Test getting findings for a specific resource."""
        response = client.get(f"/api/findings/by-resource/{sample_finding.resource_id}")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_findings_by_resource_not_found(self, client: TestClient) -> None:
        """Test getting findings for non-existent resource returns empty list."""
        response = client.get("/api/findings/by-resource/nonexistent-resource")

        assert response.status_code == 200
        data = response.json()
        assert data == []
