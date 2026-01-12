"""Operational prompts for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP


def register_ops_prompts(mcp: FastMCP) -> None:
    """Register operational prompts with the MCP server."""

    @mcp.prompt()
    def pre_scan_check(provider: str = "all") -> str:
        """Pre-scan readiness and credential verification.

        Verify system health and credentials before running a scan.
        """
        return f"""Check readiness before running a security scan for {provider}.

Steps to follow:
1. Call check_health(detailed=true) to verify:
   - API is responsive
   - PostgreSQL database is connected
   - Neo4j graph database is connected (if used)
   - All required services are healthy

2. Verify credentials:
   - If provider is "all" or "aws": call verify_credentials(provider="aws")
   - If provider is "all" or "azure": call verify_credentials(provider="azure")
   - If provider is "all" or "gcp": call verify_credentials(provider="gcp")
   - If provider is "all" or "kubernetes": call verify_credentials(provider="kubernetes")

3. For each provider, check:
   - Are credentials valid?
   - Which tools are ready to run?
   - Are there any permission issues?

4. Call list_scan_profiles() to show available options:
   - quick: 5-10 minutes, essential checks
   - comprehensive: 30-60 minutes, full audit
   - compliance-only: 15-20 minutes, compliance focus

5. Recommendations:
   - If all checks pass: Recommend appropriate scan profile
   - If credential issues: Provide remediation steps
   - If health issues: Suggest troubleshooting steps

Report readiness status with clear go/no-go recommendation.
"""

    @mcp.prompt()
    def compare_scans(baseline_scan_id: str, current_scan_id: str) -> str:
        """Compare two scan results for delta analysis.

        Identify new, resolved, and persistent findings between scans.
        """
        return f"""Compare scan results between baseline ({baseline_scan_id}) and current ({current_scan_id}).

Steps to follow:
1. Call get_scan_status("{baseline_scan_id}") to get baseline details
2. Call get_scan_status("{current_scan_id}") to get current details
3. Call search_findings with scan_id filter for both scans:
   - Baseline: search_findings(scan_id="{baseline_scan_id}")
   - Current: search_findings(scan_id="{current_scan_id}")

4. Analyze the delta:
   - NEW findings: In current but not in baseline
   - RESOLVED findings: In baseline but not in current
   - PERSISTENT findings: In both scans

5. Calculate metrics:
   - Total findings change (+ or -)
   - Critical/High severity changes
   - By provider/tool breakdown
   - Mean Time To Resolution (if findings were resolved)

6. Trend analysis:
   - Is the security posture improving or degrading?
   - Which areas show improvement?
   - Which areas need attention?

7. Report format:
   - Executive summary: Overall trend
   - New findings requiring attention
   - Resolved findings (good news)
   - Persistent high-severity items (ongoing risk)

Provide a scan comparison report suitable for security reviews.
"""

    @mcp.prompt()
    def create_remediation_plan(severity: str = "critical,high") -> str:
        """Create a prioritized remediation plan.

        Generate actionable remediation tasks for open findings.
        """
        return f"""Create a prioritized remediation plan for {severity} severity findings.

Steps to follow:
1. Call search_findings(severity="{severity}", status="open", sort_by="risk_score")
2. Call list_attack_paths(min_risk_score=70) to identify exploitable chains
3. Call get_public_exposures(risk_level="critical,high") for urgent exposure fixes

4. Prioritization framework:
   Priority 1 - Immediate (fix within 24-48 hours):
   - Critical findings with confirmed exploitability
   - Active attack path entry points
   - Internet-exposed critical vulnerabilities
   - Active credential leaks

   Priority 2 - Urgent (fix within 1 week):
   - High severity findings
   - Privilege escalation enablers
   - Compliance-critical failures

   Priority 3 - Important (fix within 1 month):
   - Medium severity findings
   - Defense-in-depth improvements
   - Non-critical compliance gaps

5. For each remediation item:
   - Finding ID and description
   - Affected resource(s)
   - Remediation steps (from get_finding_details)
   - Estimated effort (quick/half-day/multi-day)
   - Team assignment suggestion

6. Quick wins section:
   - Findings that fix multiple issues
   - Automated remediations available
   - Configuration-only changes

7. Generate remediation plan with:
   - Prioritized task list
   - Resource requirements
   - Dependencies between tasks
   - Success metrics

Output a remediation plan suitable for sprint planning.
"""

    @mcp.prompt()
    def summarize_scan_results(scan_id: str) -> str:
        """Generate an executive summary of scan results.

        Create a high-level report suitable for stakeholders.
        """
        return f"""Summarize the results of scan {scan_id} for executive reporting.

Steps to follow:
1. Call get_scan_status("{scan_id}") for scan metadata
2. Call search_findings(scan_id="{scan_id}") to get all findings
3. Call list_attack_paths and filter for paths from this scan
4. Call get_public_exposures for exposure snapshot

5. Executive Summary Structure:

   SECURITY SCAN REPORT
   ====================
   Scan ID: {scan_id}
   Date: [from scan status]
   Duration: [from scan status]
   Tools Used: [from scan status]

   KEY METRICS:
   - Total Findings: X
   - Critical: X | High: X | Medium: X | Low: X
   - Attack Paths Discovered: X
   - Public Exposures: X

   TOP RISKS:
   1. [Most critical finding with business impact]
   2. [Second most critical]
   3. [Third most critical]

   ATTACK PATHS:
   - Brief description of high-risk attack paths
   - Potential business impact

   COMPLIANCE STATUS:
   - Frameworks assessed
   - Pass/fail summary

   RECOMMENDATIONS:
   1. Immediate actions required
   2. Short-term improvements
   3. Long-term strategic changes

   TREND (if previous scans available):
   - Comparison with last scan
   - Improving/degrading areas

6. Keep language non-technical and focused on business impact
7. Include specific numbers but explain their significance
8. Provide clear action items with owners

Generate an executive summary suitable for C-level presentation.
"""
