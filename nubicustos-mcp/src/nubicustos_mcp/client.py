"""Async HTTP client for Nubicustos REST API."""

from typing import Any

import httpx

from .config import settings


class NubicustosError(Exception):
    """Base exception for Nubicustos client errors."""

    def __init__(self, message: str, status_code: int | None = None):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class NubicustosConnectionError(NubicustosError):
    """Raised when unable to connect to the Nubicustos API."""

    pass


class NubicustosAPIError(NubicustosError):
    """Raised when the API returns an error response."""

    pass


class NubicustosClient:
    """Async HTTP client wrapper for Nubicustos API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: int | None = None,
    ):
        self.base_url = (base_url or settings.api_url).rstrip("/")
        self.api_key = api_key or settings.api_key
        self.timeout = timeout or settings.request_timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None or self._client.is_closed:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-API-Key"] = self.api_key

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        """Handle API response and raise appropriate errors."""
        try:
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            try:
                error_detail = response.json().get("detail", str(e))
            except Exception:
                error_detail = response.text or str(e)
            raise NubicustosAPIError(
                f"API error ({response.status_code}): {error_detail}",
                status_code=response.status_code,
            ) from e

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request with error handling."""
        try:
            client = await self._get_client()
            response = await client.request(
                method, path, params=params, json=data
            )
            return await self._handle_response(response)
        except httpx.ConnectError as e:
            raise NubicustosConnectionError(
                f"Failed to connect to Nubicustos API at {self.base_url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise NubicustosConnectionError(
                f"Request to {path} timed out after {self.timeout}s"
            ) from e

    async def get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make a GET request to the API."""
        return await self._request("GET", path, params=params)

    async def post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a POST request to the API."""
        return await self._request("POST", path, params=params, data=data)

    async def patch(
        self, path: str, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make a PATCH request to the API."""
        return await self._request("PATCH", path, data=data)

    async def delete(self, path: str) -> dict[str, Any]:
        """Make a DELETE request to the API."""
        return await self._request("DELETE", path)

    # Scan Management
    async def list_scans(
        self,
        status: str | None = None,
        tool: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """List security scans with optional filters."""
        params = {"page": page, "page_size": page_size}
        if status:
            params["status"] = status
        if tool:
            params["tool"] = tool
        return await self.get("/api/scans", params=params)

    async def trigger_scan(
        self,
        profile: str = "comprehensive",
        target: str | None = None,
        severity_filter: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Trigger a new security scan."""
        data: dict[str, Any] = {"profile": profile, "dry_run": dry_run}
        if target:
            data["target"] = target
        if severity_filter:
            data["severity_filter"] = severity_filter
        return await self.post("/api/scans", data=data)

    async def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        """Get status and finding counts for a specific scan."""
        return await self.get(f"/api/scans/{scan_id}/status")

    async def cancel_scan(self, scan_id: str) -> dict[str, Any]:
        """Cancel a running or pending scan."""
        return await self.delete(f"/api/scans/{scan_id}")

    async def list_scan_profiles(self) -> dict[str, Any]:
        """List available scan profiles."""
        return await self.get("/api/scans/profiles/list")

    # Finding Queries
    async def search_findings(
        self,
        search: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        cloud_provider: str | None = None,
        tool: str | None = None,
        resource_type: str | None = None,
        sort_by: str = "risk_score",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """Search security findings with flexible filters."""
        params: dict[str, Any] = {
            "page": page,
            "page_size": page_size,
            "sort_by": sort_by,
        }
        if search:
            params["search"] = search
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if cloud_provider:
            params["cloud_provider"] = cloud_provider
        if tool:
            params["tool"] = tool
        if resource_type:
            params["resource_type"] = resource_type
        return await self.get("/api/findings", params=params)

    async def get_findings_summary(
        self, status: str | None = None
    ) -> dict[str, Any]:
        """Get aggregated finding statistics."""
        params = {}
        if status:
            params["status"] = status
        return await self.get("/api/findings/summary", params=params or None)

    async def get_finding_details(self, finding_id: int) -> dict[str, Any]:
        """Get complete details for a specific finding."""
        return await self.get(f"/api/findings/{finding_id}")

    async def update_finding_status(
        self,
        finding_id: int,
        status: str,
        tags: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Update a finding's status."""
        data: dict[str, Any] = {"status": status}
        if tags:
            data["tags"] = tags
        return await self.patch(f"/api/findings/{finding_id}", data=data)

    # Attack Paths
    async def list_attack_paths(
        self,
        min_risk_score: int | None = None,
        exploitability: str | None = None,
        entry_point_type: str | None = None,
        target_type: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """List discovered attack paths."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if min_risk_score is not None:
            params["min_risk_score"] = min_risk_score
        if exploitability:
            params["exploitability"] = exploitability
        if entry_point_type:
            params["entry_point_type"] = entry_point_type
        if target_type:
            params["target_type"] = target_type
        return await self.get("/api/attack-paths", params=params)

    async def get_attack_path_details(
        self, path_id: int, format: str = "json"
    ) -> dict[str, Any]:
        """Get complete attack path with nodes, edges, PoC steps."""
        params = {"format": format} if format != "json" else None
        return await self.get(f"/api/attack-paths/{path_id}", params=params)

    async def analyze_attack_paths(
        self, scan_id: str | None = None
    ) -> dict[str, Any]:
        """Trigger attack path analysis."""
        data = {"scan_id": scan_id} if scan_id else {}
        return await self.post("/api/attack-paths/analyze", data=data)

    # Security Analysis
    async def list_privesc_paths(
        self,
        min_risk_score: int | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """List IAM privilege escalation paths."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if min_risk_score is not None:
            params["min_risk_score"] = min_risk_score
        if status:
            params["status"] = status
        return await self.get("/api/privesc-paths", params=params)

    async def get_public_exposures(
        self,
        exposure_type: str | None = None,
        risk_level: str | None = None,
        is_internet_exposed: bool | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """List publicly exposed resources."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if exposure_type:
            params["exposure_type"] = exposure_type
        if risk_level:
            params["risk_level"] = risk_level
        if is_internet_exposed is not None:
            params["is_internet_exposed"] = is_internet_exposed
        return await self.get("/api/public-exposures", params=params)

    async def get_exposed_credentials(
        self,
        credential_type: str | None = None,
        source_type: str | None = None,
        remediation_status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """List discovered credential leaks."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if credential_type:
            params["credential_type"] = credential_type
        if source_type:
            params["source_type"] = source_type
        if remediation_status:
            params["remediation_status"] = remediation_status
        return await self.get("/api/exposed-credentials", params=params)

    # Cloud-Specific
    async def get_imds_checks(
        self,
        risk_level: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """List EC2 metadata service vulnerability checks."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if risk_level:
            params["risk_level"] = risk_level
        return await self.get("/api/imds-checks", params=params)

    async def get_lambda_analysis(
        self,
        risk_level: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """List Lambda function security analyses."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if risk_level:
            params["risk_level"] = risk_level
        return await self.get("/api/lambda-analysis", params=params)

    async def run_cloudfox(
        self, module_name: str, target_account: str | None = None
    ) -> dict[str, Any]:
        """Run CloudFox enumeration module."""
        data: dict[str, Any] = {"module_name": module_name}
        if target_account:
            data["target_account"] = target_account
        return await self.post("/api/cloudfox/run", data=data)

    async def run_enumerate_iam(
        self, principal_arn: str
    ) -> dict[str, Any]:
        """Enumerate IAM permissions for a principal."""
        return await self.post(
            "/api/enumerate-iam/run", data={"principal_arn": principal_arn}
        )

    # Exports
    async def export_findings(
        self,
        format: str = "json",
        severity: str | None = None,
        status: str = "open",
        cloud_provider: str | None = None,
    ) -> dict[str, Any]:
        """Generate findings export."""
        data: dict[str, Any] = {"format": format, "status": status}
        if severity:
            data["severity"] = severity
        if cloud_provider:
            data["cloud_provider"] = cloud_provider
        return await self.post("/api/exports/generate", data=data)

    async def get_export_summary(self) -> dict[str, Any]:
        """Get export-ready statistics."""
        return await self.get("/api/exports/summary")

    # System
    async def check_health(self, detailed: bool = False) -> dict[str, Any]:
        """Check API and database health status."""
        path = "/api/health/detailed" if detailed else "/api/health"
        return await self.get(path)

    async def get_sync_status(self) -> dict[str, Any]:
        """Get PostgreSQL/Neo4j synchronization status."""
        return await self.get("/api/sync/status")

    async def verify_credentials(
        self, provider: str
    ) -> dict[str, Any]:
        """Verify cloud provider credentials."""
        return await self.post(
            "/api/credentials/check-permissions", data={"provider": provider}
        )


# Global client instance
client = NubicustosClient()
