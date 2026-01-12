"""Tests for attack paths endpoints."""

from fastapi.testclient import TestClient


class TestListAttackPaths:
    """Test cases for listing attack paths."""

    def test_list_attack_paths_empty(self, client: TestClient) -> None:
        """Test listing attack paths when none exist."""
        response = client.get("/api/attack-paths")

        assert response.status_code == 200
        data = response.json()
        assert data["paths"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["page_size"] == 20

    def test_list_attack_paths_with_data(self, client: TestClient, sample_attack_path) -> None:
        """Test listing attack paths returns existing paths."""
        response = client.get("/api/attack-paths")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["paths"]) == 1
        assert data["paths"][0]["path_id"] == sample_attack_path.path_id

    def test_list_attack_paths_with_trailing_slash(self, client: TestClient) -> None:
        """Test listing paths with trailing slash works."""
        response = client.get("/api/attack-paths/")

        assert response.status_code == 200

    def test_list_attack_paths_pagination(self, client: TestClient, sample_attack_path) -> None:
        """Test attack paths pagination parameters."""
        response = client.get("/api/attack-paths?page=1&page_size=10")

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 10


class TestAttackPathsFilters:
    """Test cases for attack paths filtering."""

    def test_filter_by_min_risk_score(self, client: TestClient, sample_attack_path) -> None:
        """Test filtering by minimum risk score."""
        response = client.get("/api/attack-paths?min_risk_score=80")

        assert response.status_code == 200
        data = response.json()
        assert all(p["risk_score"] >= 80 for p in data["paths"])

    def test_filter_by_max_risk_score(self, client: TestClient, sample_attack_path) -> None:
        """Test filtering by maximum risk score."""
        response = client.get("/api/attack-paths?max_risk_score=50")

        assert response.status_code == 200
        data = response.json()
        assert all(p["risk_score"] < 50 for p in data["paths"])

    def test_filter_by_exploitability(self, client: TestClient, sample_attack_path) -> None:
        """Test filtering by exploitability."""
        response = client.get("/api/attack-paths?exploitability=confirmed")

        assert response.status_code == 200
        data = response.json()
        assert all(p["exploitability"] == "confirmed" for p in data["paths"])

    def test_filter_by_entry_point_type(self, client: TestClient, sample_attack_path) -> None:
        """Test filtering by entry point type."""
        response = client.get("/api/attack-paths?entry_point_type=public_s3")

        assert response.status_code == 200
        data = response.json()
        assert all(p["entry_point_type"] == "public_s3" for p in data["paths"])

    def test_filter_by_target_type(self, client: TestClient, sample_attack_path) -> None:
        """Test filtering by target type."""
        response = client.get("/api/attack-paths?target_type=iam_admin")

        assert response.status_code == 200
        data = response.json()
        assert all(p["target_type"] == "iam_admin" for p in data["paths"])


class TestGetAttackPath:
    """Test cases for getting individual attack paths."""

    def test_get_attack_path_by_id(self, client: TestClient, sample_attack_path) -> None:
        """Test getting an attack path by its database ID."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == sample_attack_path.id
        assert data["name"] == sample_attack_path.name

    def test_get_attack_path_not_found(self, client: TestClient) -> None:
        """Test getting a non-existent attack path returns 404."""
        response = client.get("/api/attack-paths/99999")

        assert response.status_code == 404
        assert response.json()["detail"] == "Attack path not found"

    def test_get_attack_path_by_path_id(self, client: TestClient, sample_attack_path) -> None:
        """Test getting an attack path by its path_id hash."""
        response = client.get(f"/api/attack-paths/by-path-id/{sample_attack_path.path_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["path_id"] == sample_attack_path.path_id

    def test_get_attack_path_by_path_id_not_found(self, client: TestClient) -> None:
        """Test getting by non-existent path_id returns 404."""
        response = client.get("/api/attack-paths/by-path-id/nonexistent")

        assert response.status_code == 404


class TestAttackPathStructure:
    """Test cases for attack path response structure."""

    def test_attack_path_has_nodes_and_edges(self, client: TestClient, sample_attack_path) -> None:
        """Test attack path includes nodes and edges."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}")

        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) > 0
        assert len(data["edges"]) > 0

    def test_attack_path_node_structure(self, client: TestClient, sample_attack_path) -> None:
        """Test attack path nodes have correct structure."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}")

        data = response.json()
        for node in data["nodes"]:
            assert "id" in node
            assert "type" in node
            assert "name" in node

    def test_attack_path_edge_structure(self, client: TestClient, sample_attack_path) -> None:
        """Test attack path edges have correct structure."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}")

        data = response.json()
        for edge in data["edges"]:
            assert "id" in edge
            assert "source" in edge
            assert "target" in edge
            assert "type" in edge
            assert "name" in edge

    def test_attack_path_includes_poc_steps(self, client: TestClient, sample_attack_path) -> None:
        """Test attack path includes PoC steps when available."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}")

        data = response.json()
        assert data["poc_available"] is True
        assert "poc_steps" in data
        assert len(data["poc_steps"]) > 0

    def test_attack_path_includes_mitre_tactics(
        self, client: TestClient, sample_attack_path
    ) -> None:
        """Test attack path includes MITRE tactics."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}")

        data = response.json()
        assert "mitre_tactics" in data
        assert len(data["mitre_tactics"]) > 0


class TestAttackPathSummary:
    """Test cases for attack path summary endpoint."""

    def test_get_summary_empty(self, client: TestClient) -> None:
        """Test summary with no attack paths."""
        response = client.get("/api/attack-paths/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_paths"] == 0
        assert data["critical_paths"] == 0
        assert data["avg_risk_score"] == 0.0

    def test_get_summary_with_data(self, client: TestClient, sample_attack_path) -> None:
        """Test summary returns correct statistics."""
        response = client.get("/api/attack-paths/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_paths"] == 1
        assert data["critical_paths"] == 1  # risk_score >= 80
        assert "entry_point_types" in data
        assert "target_types" in data
        assert "top_mitre_tactics" in data


class TestDeleteAttackPath:
    """Test cases for deleting attack paths."""

    def test_delete_attack_path(self, client: TestClient, sample_attack_path) -> None:
        """Test deleting an attack path."""
        response = client.delete(f"/api/attack-paths/{sample_attack_path.id}")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Attack path deleted"

        # Verify it's deleted
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}")
        assert response.status_code == 404

    def test_delete_attack_path_not_found(self, client: TestClient) -> None:
        """Test deleting non-existent attack path returns 404."""
        response = client.delete("/api/attack-paths/99999")

        assert response.status_code == 404


class TestPathFindings:
    """Test cases for getting path findings."""

    def test_get_path_findings_empty(self, client: TestClient, sample_attack_path) -> None:
        """Test getting findings for path with no findings."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}/findings")

        assert response.status_code == 200
        data = response.json()
        assert data == []

    def test_get_path_findings_not_found(self, client: TestClient) -> None:
        """Test getting findings for non-existent path returns 404."""
        response = client.get("/api/attack-paths/99999/findings")

        assert response.status_code == 404


class TestExportAttackPath:
    """Test cases for exporting attack paths."""

    def test_export_as_json(self, client: TestClient, sample_attack_path) -> None:
        """Test exporting attack path as JSON."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}/export?format=json")

        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert "name" in data

    def test_export_as_markdown(self, client: TestClient, sample_attack_path) -> None:
        """Test exporting attack path as markdown."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}/export?format=markdown")

        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "markdown"
        assert "content" in data
        assert "# Attack Path:" in data["content"]

    def test_export_default_format(self, client: TestClient, sample_attack_path) -> None:
        """Test default export format is markdown."""
        response = client.get(f"/api/attack-paths/{sample_attack_path.id}/export")

        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "markdown"

    def test_export_not_found(self, client: TestClient) -> None:
        """Test exporting non-existent path returns 404."""
        response = client.get("/api/attack-paths/99999/export")

        assert response.status_code == 404
