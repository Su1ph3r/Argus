"""Finding query tools for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP

from ..client import client


def register_finding_tools(mcp: FastMCP) -> None:
    """Register finding query tools with the MCP server."""

    @mcp.tool()
    async def search_findings(
        search: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        cloud_provider: str | None = None,
        tool: str | None = None,
        resource_type: str | None = None,
        sort_by: str = "risk_score",
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        """Search security findings with flexible filters.

        Args:
            search: Text search in finding titles
            severity: Comma-separated levels (critical,high,medium,low,info)
            status: Comma-separated statuses (open,closed,mitigated,accepted)
            cloud_provider: Filter by provider (aws,azure,gcp,kubernetes)
            tool: Filter by scanning tool
            resource_type: Filter by resource type (e.g., EC2, S3, IAM)
            sort_by: Sort field (risk_score, severity, scan_date, title)
            page: Page number
            page_size: Items per page (1-500)

        Returns:
            Paginated list of findings matching criteria
        """
        return await client.search_findings(
            search=search,
            severity=severity,
            status=status,
            cloud_provider=cloud_provider,
            tool=tool,
            resource_type=resource_type,
            sort_by=sort_by,
            page=page,
            page_size=page_size,
        )

    @mcp.tool()
    async def get_findings_summary(status: str | None = None) -> dict:
        """Get aggregated finding statistics by severity, provider, and tool.

        Args:
            status: Filter by finding status (open, closed, etc.)

        Returns:
            Summary statistics with counts by severity, provider, and tool
        """
        return await client.get_findings_summary(status=status)

    @mcp.tool()
    async def get_finding_details(finding_id: int) -> dict:
        """Get complete details for a specific finding including remediation.

        Args:
            finding_id: Database ID of the finding

        Returns:
            Full finding details with remediation commands, code snippets,
            and external resources
        """
        return await client.get_finding_details(finding_id)

    @mcp.tool()
    async def update_finding_status(
        finding_id: int,
        status: str,
        tags: dict | None = None,
    ) -> dict:
        """Update a finding's status.

        Args:
            finding_id: Database ID of the finding
            status: New status (open, closed, mitigated, accepted)
            tags: Optional tags to add to the finding

        Returns:
            Updated finding details
        """
        return await client.update_finding_status(
            finding_id=finding_id, status=status, tags=tags
        )
