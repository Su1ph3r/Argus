"""Scan execution prompts for Nubicustos MCP Server."""

from mcp.server.fastmcp import FastMCP


def register_scan_prompts(mcp: FastMCP) -> None:
    """Register scan execution prompts with the MCP server."""

    @mcp.prompt()
    def run_quick_scan() -> str:
        """Run a quick 5-10 minute scan with essential tools.

        Guides through a fast security assessment suitable for
        quick checks or CI/CD pipelines.
        """
        return """Run a quick security scan of the cloud environment.

Steps to follow:
1. First, call check_health(detailed=true) to verify the system is ready
2. Call verify_credentials for the target provider (aws, azure, gcp, or kubernetes)
3. If credentials are valid, call trigger_scan(profile="quick")
4. Monitor progress with get_scan_status using the returned scan_id
5. Once complete, call get_findings_summary to see results
6. Report any critical or high severity findings found

The quick profile runs essential checks in 5-10 minutes, covering:
- Core security configurations
- Critical misconfigurations
- High-risk vulnerabilities

If issues are found, suggest using run_full_audit for comprehensive analysis.
"""

    @mcp.prompt()
    def run_full_audit() -> str:
        """Run comprehensive 30-60 minute audit across all providers.

        Guides through a thorough security assessment covering all
        integrated tools and compliance frameworks.
        """
        return """Run a comprehensive security audit of the cloud environment.

Steps to follow:
1. Call check_health(detailed=true) to verify all dependencies are healthy
2. Call verify_credentials for each provider you want to audit
3. Call list_scan_profiles to confirm the comprehensive profile details
4. Start the audit with trigger_scan(profile="comprehensive")
5. The scan will take 30-60 minutes - periodically check status with get_scan_status
6. Once complete:
   - Call get_findings_summary for an overview
   - Call search_findings(severity="critical,high", status="open") for urgent issues
   - Call list_attack_paths(min_risk_score=70) for exploitation risks
   - Call get_public_exposures for internet-facing risks

The comprehensive profile runs all security tools including:
- AWS: Prowler, ScoutSuite, CloudSploit, Cloud Custodian
- Kubernetes: kube-bench, Kubescape, Trivy, Popeye, Polaris
- IaC: Checkov, Terrascan, tfsec
- Attack path analysis and privilege escalation detection

Provide an executive summary of the security posture when complete.
"""

    @mcp.prompt()
    def run_aws_scan() -> str:
        """Run AWS-focused security scan.

        Guides through an AWS-specific security assessment using
        Prowler, ScoutSuite, and CloudSploit.
        """
        return """Run an AWS-focused security scan.

Steps to follow:
1. Call verify_credentials(provider="aws") to validate AWS credentials
2. If valid, call trigger_scan(profile="comprehensive", target="aws")
   Or for faster results: trigger_scan(profile="quick", target="aws")
3. Monitor with get_scan_status
4. Once complete:
   - Call search_findings(cloud_provider="aws", severity="critical,high")
   - Call get_imds_checks to review EC2 metadata vulnerabilities
   - Call get_lambda_analysis for serverless security issues
   - Call list_privesc_paths for IAM privilege escalation risks

AWS tools included:
- Prowler: AWS security best practices (CIS, PCI-DSS, HIPAA)
- ScoutSuite: Multi-service security configuration
- CloudSploit: Security monitoring and alerting
- Cloud Custodian: Policy compliance

Report findings organized by AWS service and severity.
"""

    @mcp.prompt()
    def run_kubernetes_scan() -> str:
        """Run Kubernetes-focused security scan.

        Guides through a K8s-specific security assessment using
        kube-bench, Kubescape, and container scanners.
        """
        return """Run a Kubernetes-focused security scan.

Steps to follow:
1. Call verify_credentials(provider="kubernetes") to validate K8s access
2. If valid, call trigger_scan(profile="comprehensive", target="kubernetes")
   Or for faster results: trigger_scan(profile="quick", target="kubernetes")
3. Monitor with get_scan_status
4. Once complete:
   - Call search_findings(cloud_provider="kubernetes", severity="critical,high")
   - Look for container vulnerabilities, RBAC issues, and network policies
   - Check for privileged containers and security context issues

Kubernetes tools included:
- kube-bench: CIS Kubernetes Benchmark compliance
- Kubescape: NSA/CISA hardening guidelines
- kube-hunter: Penetration testing
- Trivy: Container vulnerability scanning
- Popeye: Cluster resource sanitization
- kube-linter: Static analysis
- Polaris: Best practices validation

Report findings organized by namespace and resource type.
"""

    @mcp.prompt()
    def run_iac_scan(code_path: str = "/code") -> str:
        """Run Infrastructure-as-Code security scan.

        Guides through scanning Terraform, CloudFormation, and other
        IaC templates for security issues.
        """
        return f"""Run an Infrastructure-as-Code security scan on {code_path}.

Steps to follow:
1. Call check_health to verify the scanner is ready
2. Call trigger_scan(profile="comprehensive", target="iac")
3. Monitor with get_scan_status
4. Once complete:
   - Call search_findings(tool="checkov,terrascan,tfsec")
   - Focus on findings that could create security issues when deployed

IaC tools included:
- Checkov: Terraform, CloudFormation, Kubernetes manifests, Helm charts
- Terrascan: Policy-as-code compliance
- tfsec: Terraform-specific static analysis

Common issues to report:
- Hardcoded secrets
- Overly permissive IAM policies
- Unencrypted storage
- Public network exposure
- Missing logging/monitoring

Prioritize findings that would create critical issues in production.
"""

    @mcp.prompt()
    def run_compliance_scan(framework: str = "CIS") -> str:
        """Run compliance-focused scan for specific framework.

        Guides through a compliance assessment for frameworks like
        CIS, PCI-DSS, SOC2, or HIPAA.
        """
        return f"""Run a compliance scan focused on {framework}.

Steps to follow:
1. Call check_health to verify the system is ready
2. Call verify_credentials for all relevant providers
3. Call trigger_scan(profile="compliance-only")
4. Monitor with get_scan_status
5. Once complete:
   - Call get_findings_summary to see overall compliance status
   - Call search_findings to explore specific control failures

Compliance frameworks supported:
- CIS: Center for Internet Security benchmarks
- PCI-DSS: Payment Card Industry Data Security Standard
- SOC2: Service Organization Control 2
- HIPAA: Health Insurance Portability and Accountability Act
- NIST: National Institute of Standards and Technology
- AWS Well-Architected: AWS best practices

For the {framework} framework, focus on:
- Control coverage percentage
- Critical control failures
- Remediation priorities
- Evidence collection for audit

Generate a compliance report suitable for auditors or stakeholders.
"""
