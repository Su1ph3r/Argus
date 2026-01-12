"""Export tools for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP

from ..client import client


def register_export_tools(mcp: FastMCP) -> None:
    """Register export tools with the MCP server."""

    @mcp.tool()
    async def export_findings(
        format: str = "json",
        severity: str | None = None,
        status: str = "open",
        cloud_provider: str | None = None,
    ) -> dict:
        """Export findings as CSV or JSON.

        Args:
            format: Export format (csv, json)
            severity: Comma-separated severity filter (critical,high,medium,low)
            status: Status filter (default: open)
            cloud_provider: Cloud provider filter (aws, azure, gcp, kubernetes)

        Returns:
            Export metadata with download URL or tracking ID
        """
        return await client.export_findings(
            format=format,
            severity=severity,
            status=status,
            cloud_provider=cloud_provider,
        )

    @mcp.tool()
    async def get_export_summary() -> dict:
        """Get export-ready statistics.

        Returns:
            Summary statistics suitable for export including finding counts
            by severity, provider, and status
        """
        return await client.get_export_summary()
