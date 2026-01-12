"""Attack path tools for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP

from ..client import client


def register_attack_path_tools(mcp: FastMCP) -> None:
    """Register attack path tools with the MCP server."""

    @mcp.tool()
    async def list_attack_paths(
        min_risk_score: int | None = None,
        exploitability: str | None = None,
        entry_point_type: str | None = None,
        target_type: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List discovered attack paths ordered by risk score.

        Args:
            min_risk_score: Minimum risk score filter (0-100)
            exploitability: Filter by exploitability (confirmed, likely, theoretical)
            entry_point_type: Filter by entry point type
            target_type: Filter by target type
            page: Page number
            page_size: Items per page

        Returns:
            Paginated list of attack paths with risk scores and MITRE mappings
        """
        return await client.list_attack_paths(
            min_risk_score=min_risk_score,
            exploitability=exploitability,
            entry_point_type=entry_point_type,
            target_type=target_type,
            page=page,
            page_size=page_size,
        )

    @mcp.tool()
    async def get_attack_path_details(path_id: int, format: str = "json") -> dict:
        """Get complete attack path with nodes, edges, PoC steps, and MITRE mappings.

        Args:
            path_id: Database ID of the attack path
            format: Output format - json or markdown (for reports)

        Returns:
            Full attack path details including exploitation steps
        """
        return await client.get_attack_path_details(path_id=path_id, format=format)

    @mcp.tool()
    async def analyze_attack_paths(scan_id: str | None = None) -> dict:
        """Trigger attack path analysis to discover new paths from findings.

        Args:
            scan_id: Optional scan ID to analyze (uses latest if not specified)

        Returns:
            Analysis results with newly discovered attack paths
        """
        return await client.analyze_attack_paths(scan_id=scan_id)
