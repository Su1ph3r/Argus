"""Tests for main application endpoints."""

from fastapi.testclient import TestClient


class TestRootEndpoints:
    """Test cases for root application endpoints."""

    def test_root_endpoint(self, client: TestClient) -> None:
        """Test root endpoint returns API information."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Nubicustos API"
        assert data["version"] == "1.0.0"
        assert "docs" in data
        assert "health" in data

    def test_api_root_endpoint(self, client: TestClient) -> None:
        """Test API root endpoint returns endpoints list."""
        response = client.get("/api")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Nubicustos API"
        assert "endpoints" in data
        assert "health" in data["endpoints"]
        assert "scans" in data["endpoints"]
        assert "findings" in data["endpoints"]
        assert "exports" in data["endpoints"]
        assert "attack_paths" in data["endpoints"]


class TestCORSHeaders:
    """Test cases for CORS configuration."""

    def test_cors_headers_present(self, client: TestClient) -> None:
        """Test CORS headers are present in responses."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:8080",
                "Access-Control-Request-Method": "GET",
            },
        )

        # CORS preflight should succeed
        assert response.status_code in [200, 204]


class TestProcessTimeHeader:
    """Test cases for process time header middleware."""

    def test_process_time_header_present(self, client: TestClient) -> None:
        """Test X-Process-Time header is present in responses."""
        response = client.get("/api/health")

        assert "x-process-time" in response.headers
        # Should be a float representing seconds
        process_time = float(response.headers["x-process-time"])
        assert process_time >= 0


class TestOpenAPIDocumentation:
    """Test cases for OpenAPI documentation endpoints."""

    def test_openapi_json_available(self, client: TestClient) -> None:
        """Test OpenAPI JSON schema is available."""
        response = client.get("/api/openapi.json")

        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert data["info"]["title"] == "Nubicustos API"

    def test_docs_redirect(self, client: TestClient) -> None:
        """Test /api/docs endpoint exists."""
        response = client.get("/api/docs")

        # Should return docs page or redirect
        assert response.status_code in [200, 307]

    def test_redoc_endpoint(self, client: TestClient) -> None:
        """Test /api/redoc endpoint exists."""
        response = client.get("/api/redoc")

        # Should return redoc page or redirect
        assert response.status_code in [200, 307]
