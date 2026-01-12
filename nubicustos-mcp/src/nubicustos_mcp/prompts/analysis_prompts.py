"""Analysis prompts for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP


def register_analysis_prompts(mcp: FastMCP) -> None:
    """Register analysis prompts with the MCP server."""

    @mcp.prompt()
    def analyze_security_posture() -> str:
        """Analyze the overall security posture of the environment.

        Comprehensive assessment including findings, attack paths,
        exposures, and compliance status.
        """
        return """Analyze the overall security posture of the cloud environment.

Steps to follow:
1. Call get_findings_summary() to get an overview of all findings
2. Call list_attack_paths(min_risk_score=60) to find high-risk attack paths
3. Call get_public_exposures() to check for internet-exposed resources
4. Call get_exposed_credentials() to check for credential leaks
5. Call list_privesc_paths() to assess IAM privilege escalation risks

Analysis framework:
1. Overall Risk Level: Assess as Critical/High/Medium/Low based on:
   - Number and severity of open findings
   - Presence of exploitable attack paths
   - Internet exposure of sensitive resources
   - Active credential leaks

2. Top 3 Most Concerning Issues: Identify the most impactful problems

3. Quick Wins: Low-effort, high-impact fixes that can be done immediately

4. Strategic Recommendations: Longer-term security improvements

5. Compliance Gaps: Any framework compliance issues discovered

Provide an executive summary suitable for security leadership.
"""

    @mcp.prompt()
    def triage_finding(finding_id: int) -> str:
        """Generate a triage recommendation for a specific finding.

        Detailed analysis of a finding with remediation guidance.
        """
        return f"""Triage security finding ID {finding_id}.

Steps to follow:
1. Call get_finding_details({finding_id}) to get full context
2. Review the finding details including:
   - Severity and risk score
   - Affected resource
   - Exploitability assessment
   - CVSS score if applicable
   - Compliance framework mappings

3. Assess business impact:
   - What data or systems could be compromised?
   - Is the resource internet-facing?
   - Is it in a production environment?

4. Recommend one of these actions:
   - IMMEDIATE ACTION: Critical risk, exploit available, fix now
   - SCHEDULED REMEDIATION: High risk, plan fix within sprint
   - ACCEPT RISK: Low impact after mitigating controls review
   - FALSE POSITIVE: Not applicable to this environment

5. If remediation is needed:
   - Provide specific steps from the remediation guidance
   - Include CLI commands or Terraform snippets if available
   - Estimate effort (quick fix, half-day, multi-day)

6. Optionally call update_finding_status to update the finding status
"""

    @mcp.prompt()
    def explain_attack_path(path_id: int) -> str:
        """Explain an attack path in business terms.

        Translate technical attack chains into executive-friendly
        explanations with business impact.
        """
        return f"""Explain attack path ID {path_id} in business terms.

Steps to follow:
1. Call get_attack_path_details({path_id}) to get the full path
2. Analyze the attack chain:
   - Entry point: How an attacker gains initial access
   - Progression: Steps to escalate privileges or move laterally
   - Target: What the attacker ultimately compromises
   - Impact: Business consequences of successful exploitation

3. Explain in plain English:
   - "An attacker could..." narrative
   - Avoid jargon - explain technical terms
   - Focus on business impact, not technical details

4. Risk assessment:
   - Likelihood: How easy is this to exploit?
   - Impact: What's at stake?
   - MITRE ATT&CK mapping: Standard attack framework reference

5. Defensive recommendations:
   - Which link in the chain is easiest to break?
   - Quick mitigations vs. architectural changes
   - Detection opportunities

Provide a summary suitable for a non-technical executive.
"""

    @mcp.prompt()
    def compliance_gap_analysis(framework: str = "CIS") -> str:
        """Analyze compliance gaps for a specific framework.

        Detailed assessment of compliance control failures.
        """
        return f"""Analyze compliance gaps for the {framework} framework.

Steps to follow:
1. Call search_findings(status="open") and filter for {framework} compliance mappings
2. Group findings by control category:
   - Identity and Access Management
   - Network Security
   - Data Protection
   - Logging and Monitoring
   - Incident Response

3. For each category:
   - List failing controls with control IDs
   - Assess severity of gaps
   - Identify root causes (configuration, architecture, process)

4. Prioritize remediation:
   - Critical controls that must pass for certification
   - Quick wins that fix multiple controls
   - Systemic issues requiring architectural changes

5. Generate compliance status report:
   - Overall compliance percentage
   - Controls passing/failing/not-assessed
   - Trending (improving or degrading)

Framework-specific considerations for {framework}:
- Key mandatory controls
- Common audit findings
- Evidence requirements

Output a compliance gap report suitable for audit preparation.
"""

    @mcp.prompt()
    def investigate_resource(resource_id: str) -> str:
        """Investigate all security issues for a specific resource.

        Deep-dive into a single resource's security profile.
        """
        return f"""Investigate security issues for resource: {resource_id}

Steps to follow:
1. Call search_findings with resource filter to find all related findings
2. Call list_attack_paths and filter for paths involving this resource
3. Call get_public_exposures and check if this resource is exposed
4. If AWS resource:
   - Check get_imds_checks for EC2 instances
   - Check get_lambda_analysis for Lambda functions

5. Build a security profile:
   - All open findings affecting this resource
   - Risk score assessment
   - Attack path involvement
   - Public exposure status
   - Historical finding trends

6. Risk summary:
   - Is this resource a high-value target?
   - Is it part of any attack chains?
   - What's the blast radius if compromised?

7. Recommendations:
   - Immediate actions if compromised
   - Remediation priorities
   - Monitoring recommendations

Provide a comprehensive security assessment for this resource.
"""

    @mcp.prompt()
    def analyze_iam_risks() -> str:
        """Analyze IAM privilege escalation and permission risks.

        Review IAM configuration for excessive permissions and
        privilege escalation paths.
        """
        return """Analyze IAM privilege escalation and permission risks.

Steps to follow:
1. Call list_privesc_paths(min_risk_score=50) to get escalation paths
2. Call search_findings(resource_type="IAM", severity="critical,high")
3. Call get_exposed_credentials to check for leaked IAM credentials

4. Analyze privilege escalation risks:
   - Source principals with escalation potential
   - Target roles that can be assumed
   - Escalation methods (AssumeRole, policy manipulation, etc.)
   - MITRE ATT&CK technique mappings

5. Common IAM issues to check:
   - Overly permissive policies (*:* permissions)
   - Missing MFA requirements
   - Unused roles and policies
   - Cross-account trust misconfigurations
   - Service-linked roles with excessive access

6. Recommendations:
   - Least privilege improvements
   - Role trust policy hardening
   - Credential rotation needs
   - MFA enforcement gaps

Provide an IAM security assessment with prioritized remediation steps.
"""

    @mcp.prompt()
    def analyze_public_exposure() -> str:
        """Analyze internet-facing attack surface.

        Review all publicly accessible resources and their risk levels.
        """
        return """Analyze the internet-facing attack surface.

Steps to follow:
1. Call get_public_exposures() to list all exposed resources
2. Call search_findings(status="open") and filter for network-related findings
3. Group exposures by type:
   - Public S3 buckets / storage
   - Open security groups / firewalls
   - Publicly accessible databases
   - Exposed management interfaces
   - API endpoints without authentication

4. Risk assessment for each exposure:
   - What data or functionality is exposed?
   - Is authentication required?
   - Are there known vulnerabilities?
   - Geographic exposure (worldwide vs. specific regions)

5. Attack surface metrics:
   - Total number of public resources
   - Critical exposures requiring immediate action
   - Unnecessary exposures that should be removed

6. Recommendations:
   - Immediate: Critical exposures to lock down
   - Short-term: Review and restrict access
   - Long-term: Network architecture improvements

Provide an attack surface report with remediation priorities.
"""

    @mcp.prompt()
    def analyze_lambda_security() -> str:
        """Analyze serverless function security.

        Review Lambda functions for secrets, vulnerabilities,
        and insecure patterns.
        """
        return """Analyze Lambda function security.

Steps to follow:
1. Call get_lambda_analysis() to get all analyzed functions
2. Call search_findings(resource_type="Lambda", severity="critical,high")

3. Categorize issues:
   - Hardcoded secrets and credentials
   - Exposed API keys
   - Vulnerable dependencies
   - Insecure code patterns (eval, exec, etc.)
   - Overly permissive IAM roles

4. For each function with issues:
   - Runtime and handler information
   - Specific secrets or vulnerabilities found
   - Risk level assessment
   - VPC configuration (if applicable)

5. Common Lambda security issues:
   - Environment variables with secrets
   - Outdated dependencies with CVEs
   - Function URL without authentication
   - Excessive timeout/memory (potential for abuse)
   - Missing input validation

6. Recommendations:
   - Secret management (use Secrets Manager/Parameter Store)
   - Dependency updates
   - Code fixes for insecure patterns
   - IAM role right-sizing

Provide a Lambda security assessment with remediation guidance.
"""
