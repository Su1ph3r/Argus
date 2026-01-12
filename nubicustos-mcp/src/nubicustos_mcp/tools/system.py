"""System tools for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP

from ..client import client


def register_system_tools(mcp: FastMCP) -> None:
    """Register system tools with the MCP server."""

    @mcp.tool()
    async def check_health(detailed: bool = False) -> dict:
        """Check Nubicustos API and database health status.

        Args:
            detailed: If true, include dependency status (PostgreSQL, Neo4j)

        Returns:
            Health status of the API and its dependencies
        """
        return await client.check_health(detailed=detailed)

    @mcp.tool()
    async def get_sync_status() -> dict:
        """Get PostgreSQL/Neo4j synchronization status.

        Returns:
            Sync status including asset counts, lag estimation, and discrepancies
        """
        return await client.get_sync_status()

    @mcp.tool()
    async def verify_credentials(provider: str) -> dict:
        """Verify cloud provider credentials are valid and have required permissions.

        Args:
            provider: Cloud provider to check (aws, azure, gcp, kubernetes)

        Returns:
            Credential status with tool readiness information
        """
        return await client.verify_credentials(provider=provider)
