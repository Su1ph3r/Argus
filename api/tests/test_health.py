"""Tests for health check endpoints."""

from fastapi.testclient import TestClient


class TestHealthEndpoints:
    """Test cases for health check endpoints."""

    def test_health_check_returns_healthy(self, client: TestClient) -> None:
        """Test basic health check returns healthy status."""
        response = client.get("/api/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["database"] == "healthy"
        assert "timestamp" in data
        assert data["version"] == "1.0.0"

    def test_health_check_with_trailing_slash(self, client: TestClient) -> None:
        """Test health check with trailing slash works."""
        response = client.get("/api/health/")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_detailed_health_check(self, client: TestClient) -> None:
        """Test detailed health check returns all service statuses."""
        response = client.get("/api/health/detailed")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "services" in data
        assert "timestamp" in data
        assert isinstance(data["services"], list)

    def test_detailed_health_includes_postgresql_status(self, client: TestClient) -> None:
        """Test detailed health includes PostgreSQL service status."""
        response = client.get("/api/health/detailed")

        assert response.status_code == 200
        data = response.json()
        services = {s["name"]: s for s in data["services"]}
        assert "postgresql" in services
        assert services["postgresql"]["status"] == "healthy"

    def test_detailed_health_includes_table_statuses(self, client: TestClient, sample_scan) -> None:
        """Test detailed health includes scans and findings table statuses."""
        response = client.get("/api/health/detailed")

        assert response.status_code == 200
        data = response.json()
        services = {s["name"]: s for s in data["services"]}
        assert "scans_table" in services
        assert "findings_table" in services


class TestHealthResponseFormat:
    """Test cases for health response format validation."""

    def test_health_response_has_required_fields(self, client: TestClient) -> None:
        """Test health response contains all required fields."""
        response = client.get("/api/health")

        data = response.json()
        required_fields = ["status", "database", "timestamp", "version"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

    def test_detailed_health_service_format(self, client: TestClient) -> None:
        """Test detailed health service entries have correct format."""
        response = client.get("/api/health/detailed")

        data = response.json()
        for service in data["services"]:
            assert "name" in service
            assert "status" in service
            assert service["status"] in ["healthy", "unhealthy"]
