"""Security analysis tools for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP

from ..client import client


def register_security_tools(mcp: FastMCP) -> None:
    """Register security analysis tools with the MCP server."""

    @mcp.tool()
    async def list_privesc_paths(
        min_risk_score: int | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List IAM privilege escalation paths.

        Args:
            min_risk_score: Minimum risk score filter (0-100)
            status: Filter by status (open, mitigated)
            page: Page number
            page_size: Items per page

        Returns:
            List of privilege escalation paths with source/target principals
            and MITRE technique mappings
        """
        return await client.list_privesc_paths(
            min_risk_score=min_risk_score,
            status=status,
            page=page,
            page_size=page_size,
        )

    @mcp.tool()
    async def get_public_exposures(
        exposure_type: str | None = None,
        risk_level: str | None = None,
        is_internet_exposed: bool | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List publicly exposed resources (S3 buckets, open ports, etc.).

        Args:
            exposure_type: Filter by type (PublicS3Bucket, OpenSecurityGroup, etc.)
            risk_level: Filter by risk level (critical, high, medium, low)
            is_internet_exposed: Filter by internet exposure
            page: Page number
            page_size: Items per page

        Returns:
            List of public exposures with risk assessments
        """
        return await client.get_public_exposures(
            exposure_type=exposure_type,
            risk_level=risk_level,
            is_internet_exposed=is_internet_exposed,
            page=page,
            page_size=page_size,
        )

    @mcp.tool()
    async def get_exposed_credentials(
        credential_type: str | None = None,
        source_type: str | None = None,
        remediation_status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List discovered credential leaks.

        Args:
            credential_type: Filter by type (AWS_ACCESS_KEY, DATABASE_PASSWORD, etc.)
            source_type: Filter by source (Environment variables, Config files, etc.)
            remediation_status: Filter by status (pending, in_progress, resolved)
            page: Page number
            page_size: Items per page

        Returns:
            List of exposed credentials with source locations and risk levels
        """
        return await client.get_exposed_credentials(
            credential_type=credential_type,
            source_type=source_type,
            remediation_status=remediation_status,
            page=page,
            page_size=page_size,
        )
