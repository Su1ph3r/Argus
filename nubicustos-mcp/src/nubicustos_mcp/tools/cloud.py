"""Cloud-specific tools for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP

from ..client import client


def register_cloud_tools(mcp: FastMCP) -> None:
    """Register cloud-specific tools with the MCP server."""

    @mcp.tool()
    async def get_imds_checks(
        risk_level: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List EC2 metadata service vulnerability checks.

        Args:
            risk_level: Filter by risk level (critical, high, medium, low)
            page: Page number
            page_size: Items per page

        Returns:
            List of IMDS checks including IMDSv1 status, hop limits,
            SSRF vulnerabilities, and container credential exposure
        """
        return await client.get_imds_checks(
            risk_level=risk_level, page=page, page_size=page_size
        )

    @mcp.tool()
    async def get_lambda_analysis(
        risk_level: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List Lambda function security analyses.

        Args:
            risk_level: Filter by risk level (critical, high, medium, low)
            page: Page number
            page_size: Items per page

        Returns:
            List of Lambda functions with detected secrets, hardcoded credentials,
            vulnerable dependencies, and insecure code patterns
        """
        return await client.get_lambda_analysis(
            risk_level=risk_level, page=page, page_size=page_size
        )

    @mcp.tool()
    async def run_cloudfox(
        module_name: str,
        target_account: str | None = None,
    ) -> dict:
        """Run CloudFox enumeration module.

        Args:
            module_name: CloudFox module to run (e.g., org-relationships,
                        org-principals, instances, etc.)
            target_account: Optional AWS account ID to target

        Returns:
            CloudFox enumeration results for the specified module
        """
        return await client.run_cloudfox(
            module_name=module_name, target_account=target_account
        )

    @mcp.tool()
    async def run_enumerate_iam(principal_arn: str) -> dict:
        """Enumerate IAM permissions for a principal.

        Args:
            principal_arn: ARN of the IAM principal to enumerate

        Returns:
            Permission enumeration results including confirmed/denied permissions,
            privesc capability, admin capability, and data access capability
        """
        return await client.run_enumerate_iam(principal_arn=principal_arn)
