"""MCP resources for Nubicustos data access."""

from mcp.server.fastmcp import FastMCP

from ..client import client, NubicustosError


def register_resources(mcp: FastMCP) -> None:
    """Register MCP resources with the server."""

    @mcp.resource("nubicustos://summary")
    async def get_summary() -> str:
        """Get current security posture summary.

        Returns finding counts, recent scans, and critical issues
        for quick context on the current security state.
        """
        try:
            summary = await client.get_findings_summary()
            health = await client.check_health(detailed=True)
            return f"""Security Posture Summary
========================

Health Status: {health.get('status', 'unknown')}

Finding Summary:
{_format_summary(summary)}

Use the search_findings tool to explore specific findings.
Use the trigger_scan tool to run a new security assessment.
"""
        except NubicustosError as e:
            return f"Error fetching summary: {e.message}"

    @mcp.resource("nubicustos://profiles")
    async def get_profiles() -> str:
        """Get available scan profiles with descriptions and durations.

        Useful for understanding which scan profile to use for different
        scenarios (quick assessment vs comprehensive audit).
        """
        try:
            profiles = await client.list_scan_profiles()
            return f"""Available Scan Profiles
=======================

{_format_profiles(profiles)}

Use the trigger_scan tool with the profile parameter to start a scan.
"""
        except NubicustosError as e:
            return f"Error fetching profiles: {e.message}"

    @mcp.resource("nubicustos://tools")
    async def get_tools_info() -> str:
        """Get information about available scanning tools.

        Lists all security scanning tools integrated with Nubicustos
        and their capabilities.
        """
        return """Available Security Scanning Tools
=================================

AWS Tools:
- Prowler: AWS security best practices and compliance
- ScoutSuite: Multi-cloud security auditing
- CloudSploit: Cloud security configuration monitoring
- Cloud Custodian: Cloud resource management and policies
- CloudMapper: AWS network visualization
- Cartography: Infrastructure graph analysis

Kubernetes Tools:
- kube-bench: CIS Kubernetes Benchmark
- Kubescape: Kubernetes security scanner
- kube-hunter: Kubernetes penetration testing
- Trivy: Container vulnerability scanning
- Grype: Container vulnerability scanner
- Popeye: Kubernetes cluster sanitizer
- kube-linter: Static analysis for Kubernetes
- Polaris: Kubernetes best practices

IaC Tools:
- Checkov: Infrastructure as Code analysis
- Terrascan: Static code analyzer for IaC
- tfsec: Terraform static analysis

Use trigger_scan with a profile to run these tools.
"""

    @mcp.resource("nubicustos://settings")
    async def get_settings() -> str:
        """Get current application settings.

        Shows configured preferences for scans, data retention,
        and notifications.
        """
        return """Nubicustos Settings
==================

Configuration is managed via environment variables:
- NUBICUSTOS_MCP_API_URL: API endpoint (default: http://localhost:8000)
- NUBICUSTOS_MCP_API_KEY: Optional API key for authentication

Use check_health to verify connectivity.
Use verify_credentials to check cloud provider authentication.
"""

    @mcp.resource("nubicustos://scans/{scan_id}")
    async def get_scan_details(scan_id: str) -> str:
        """Get details for a specific scan.

        Args:
            scan_id: UUID of the scan to retrieve
        """
        try:
            status = await client.get_scan_status(scan_id)
            return f"""Scan Details: {scan_id}
{'=' * (15 + len(scan_id))}

Status: {status.get('status', 'unknown')}
Tool: {status.get('tool', 'N/A')}
Started: {status.get('started_at', 'N/A')}
Completed: {status.get('completed_at', 'N/A')}

Finding Counts:
- Critical: {status.get('critical_findings', 0)}
- High: {status.get('high_findings', 0)}
- Medium: {status.get('medium_findings', 0)}
- Low: {status.get('low_findings', 0)}

Use search_findings with scan_id filter to see findings from this scan.
"""
        except NubicustosError as e:
            return f"Error fetching scan {scan_id}: {e.message}"

    @mcp.resource("nubicustos://findings/{severity}")
    async def get_findings_by_severity(severity: str) -> str:
        """Get findings filtered by severity level.

        Args:
            severity: Severity level (critical, high, medium, low, info)
        """
        try:
            findings = await client.search_findings(
                severity=severity, status="open", page_size=10
            )
            items = findings.get("items", [])
            total = findings.get("total", 0)

            if not items:
                return f"No open {severity} findings found."

            result = f"""{severity.upper()} Severity Findings ({total} total)
{'=' * 40}

"""
            for f in items[:10]:
                result += f"""- [{f.get('id')}] {f.get('title', 'Untitled')}
  Resource: {f.get('resource_type', 'N/A')} - {f.get('resource_name', 'N/A')}
  Provider: {f.get('cloud_provider', 'N/A')}
  Risk Score: {f.get('risk_score', 'N/A')}

"""

            if total > 10:
                result += f"\n... and {total - 10} more. Use search_findings for full list."

            return result
        except NubicustosError as e:
            return f"Error fetching {severity} findings: {e.message}"


def _format_summary(summary: dict) -> str:
    """Format finding summary for display."""
    by_severity = summary.get("by_severity", {})
    by_provider = summary.get("by_provider", {})

    result = "By Severity:\n"
    for sev, count in by_severity.items():
        result += f"  - {sev}: {count}\n"

    result += "\nBy Provider:\n"
    for provider, count in by_provider.items():
        result += f"  - {provider}: {count}\n"

    return result


def _format_profiles(profiles: dict) -> str:
    """Format scan profiles for display."""
    items = profiles.get("profiles", profiles.get("items", []))
    if not items:
        return "No profiles available."

    result = ""
    for p in items:
        name = p.get("name", "Unknown")
        desc = p.get("description", "No description")
        duration = p.get("estimated_duration", "Unknown")
        result += f"- {name}: {desc}\n  Duration: {duration}\n\n"

    return result
