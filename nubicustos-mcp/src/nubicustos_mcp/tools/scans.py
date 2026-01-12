"""Scan management tools for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP

from ..client import client


def register_scan_tools(mcp: FastMCP) -> None:
    """Register scan management tools with the MCP server."""

    @mcp.tool()
    async def list_scans(
        status: str | None = None,
        tool: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List security scans with optional filters.

        Args:
            status: Filter by status (pending, running, completed, failed)
            tool: Filter by scanning tool name
            page: Page number (1-indexed)
            page_size: Items per page (1-100)

        Returns:
            Paginated list of scans with metadata
        """
        return await client.list_scans(
            status=status, tool=tool, page=page, page_size=page_size
        )

    @mcp.tool()
    async def trigger_scan(
        profile: str = "comprehensive",
        target: str | None = None,
        severity_filter: str | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Trigger a new security scan.

        Args:
            profile: Scan profile - quick (5-10 min), comprehensive (30-60 min),
                     or compliance-only (15-20 min)
            target: Optional specific target to scan
            severity_filter: Comma-separated severity levels (critical,high,medium,low)
            dry_run: If true, preview commands without executing

        Returns:
            Created scan details with UUID for tracking
        """
        return await client.trigger_scan(
            profile=profile,
            target=target,
            severity_filter=severity_filter,
            dry_run=dry_run,
        )

    @mcp.tool()
    async def get_scan_status(scan_id: str) -> dict:
        """Get current status and finding counts for a specific scan.

        Args:
            scan_id: UUID of the scan to check

        Returns:
            Scan status including finding counts by severity
        """
        return await client.get_scan_status(scan_id)

    @mcp.tool()
    async def cancel_scan(scan_id: str) -> dict:
        """Cancel a running or pending scan.

        Args:
            scan_id: UUID of the scan to cancel

        Returns:
            Confirmation of cancellation
        """
        return await client.cancel_scan(scan_id)

    @mcp.tool()
    async def list_scan_profiles() -> dict:
        """List available scan profiles with descriptions.

        Returns:
            Available profiles with tool lists and estimated durations
        """
        return await client.list_scan_profiles()
