# Nubicustos MCP Integration Examples

This guide provides comprehensive examples for integrating Nubicustos with Claude Desktop and other LLM clients using the Model Context Protocol (MCP).

## Table of Contents

- [Claude Desktop Configuration](#claude-desktop-configuration)
- [Common Workflows](#common-workflows)
- [Error Handling Patterns](#error-handling-patterns)
- [End-to-End Examples](#end-to-end-examples)

---

## Claude Desktop Configuration

### Basic Setup

Add the Nubicustos MCP server to your Claude Desktop configuration.

**Location:**
- macOS/Linux: `~/.config/claude/config.json`
- Windows: `%APPDATA%\Claude\config.json`

### Minimal Configuration

```json
{
  "mcpServers": {
    "nubicustos": {
      "command": "python",
      "args": ["-m", "nubicustos_mcp.server"],
      "env": {
        "NUBICUSTOS_MCP_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

### Configuration with API Key

For production deployments with API authentication enabled:

```json
{
  "mcpServers": {
    "nubicustos": {
      "command": "python",
      "args": ["-m", "nubicustos_mcp.server"],
      "env": {
        "NUBICUSTOS_MCP_API_URL": "http://localhost:8000",
        "NUBICUSTOS_MCP_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Using Virtual Environment

If you installed nubicustos-mcp in a virtual environment:

```json
{
  "mcpServers": {
    "nubicustos": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "nubicustos_mcp.server"],
      "env": {
        "NUBICUSTOS_MCP_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

### Remote API Configuration

For connecting to a remote Nubicustos instance:

```json
{
  "mcpServers": {
    "nubicustos": {
      "command": "python",
      "args": ["-m", "nubicustos_mcp.server"],
      "env": {
        "NUBICUSTOS_MCP_API_URL": "https://nubicustos.yourdomain.com",
        "NUBICUSTOS_MCP_API_KEY": "your-production-api-key",
        "NUBICUSTOS_MCP_REQUEST_TIMEOUT": "60"
      }
    }
  }
}
```

### Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `NUBICUSTOS_MCP_API_URL` | `http://localhost:8000` | Nubicustos REST API base URL |
| `NUBICUSTOS_MCP_API_KEY` | None | API key for authentication (optional) |
| `NUBICUSTOS_MCP_REQUEST_TIMEOUT` | `30` | HTTP request timeout in seconds |
| `NUBICUSTOS_MCP_MAX_RETRIES` | `3` | Maximum retry attempts for failed requests |

---

## Common Workflows

### Triage Workflow

Use this workflow to quickly triage and prioritize security findings.

**Step 1: Get Security Overview**

```
User: "What's my current security posture?"

Claude uses:
- get_findings_summary() to get aggregate statistics
- list_attack_paths(min_risk_score=70) to find critical paths
- get_public_exposures() to check attack surface
```

**Step 2: Investigate Critical Findings**

```
User: "Show me the most critical findings to address"

Claude uses:
- search_findings(severity="critical", status="open", sort_by="risk_score")
- For each finding: get_finding_details(finding_id) for context
```

**Step 3: Mark as Addressed**

```
User: "I've fixed finding 123, mark it as mitigated"

Claude uses:
- update_finding_status(finding_id=123, status="mitigated",
    tags={"remediated_by": "user", "ticket": "JIRA-456"})
```

### Analysis Workflow

Deep-dive analysis for understanding security risks.

**Analyze Attack Paths:**

```
User: "Explain the attack path from public S3 to data exfiltration"

Claude uses:
- list_attack_paths(entry_point_type="public_s3", target_type="data_exfiltration")
- get_attack_path_details(path_id) for full node/edge graph
- Uses explain_attack_path prompt for business-friendly explanation
```

**IAM Risk Analysis:**

```
User: "What are our IAM privilege escalation risks?"

Claude uses:
- list_privesc_paths(min_risk_score=50)
- run_enumerate_iam(principal_arn="arn:aws:iam::*:user/*") for permission enumeration
- Uses analyze_iam_risks prompt for comprehensive analysis
```

**Resource Investigation:**

```
User: "What's wrong with our production-db instance?"

Claude uses:
- search_findings(search="production-db")
- get_finding_details() for each related finding
- Uses investigate_resource prompt
```

### Reporting Workflow

Generate reports and exports for stakeholders.

**Executive Summary:**

```
User: "Generate an executive summary of last week's scan"

Claude uses:
- list_scans(status="completed") to find recent scans
- get_findings_summary() for statistics
- Uses summarize_scan_results prompt
```

**Compliance Export:**

```
User: "Export all critical AWS findings for the security review"

Claude uses:
- export_findings(format="csv", severity="critical", cloud_provider="aws")
```

**Comparison Report:**

```
User: "Compare this scan with last month's baseline"

Claude uses:
- list_scans() to find both scans
- get_scan_status() for each
- Uses compare_scans prompt
```

---

## Error Handling Patterns

### Connection Errors

When the Nubicustos API is unreachable:

```
Error: NubicustosConnectionError: Failed to connect to Nubicustos API at http://localhost:8000

Resolution steps:
1. Verify the stack is running: docker compose ps
2. Check API health: curl http://localhost:8000/api/health
3. Verify NUBICUSTOS_MCP_API_URL is correct in config
4. Check for network/firewall issues
```

**Claude Response Pattern:**

```
"I'm unable to connect to the Nubicustos API. Let me check the health status first."
[Uses check_health(detailed=True)]
"The API appears to be down. Please verify the Docker stack is running with: docker compose ps"
```

### Authentication Errors

When API key is invalid or missing:

```
Error: NubicustosAPIError: API error (401): Invalid or missing API key

Resolution steps:
1. Verify API_KEY is set in Nubicustos .env
2. Update NUBICUSTOS_MCP_API_KEY in Claude config
3. Restart Claude Desktop to reload config
```

**Claude Response Pattern:**

```
"Authentication failed. The API key may be incorrect or missing. Please verify:
1. The API_KEY environment variable is set in your Nubicustos .env file
2. The NUBICUSTOS_MCP_API_KEY matches in your Claude config
3. Restart Claude Desktop after making changes"
```

### Resource Not Found Errors

When querying non-existent resources:

```
Error: NubicustosAPIError: API error (404): Scan not found

Claude Response Pattern:
"That scan doesn't exist. Let me list available scans..."
[Uses list_scans() to show available scans]
```

### Rate Limiting

When hitting API rate limits:

```
Error: NubicustosAPIError: API error (429): Rate limit exceeded. Please retry later.

Claude Response Pattern:
"The API rate limit has been reached. I'll wait a moment before retrying..."
[Waits, then retries with exponential backoff]
```

### Timeout Handling

For long-running operations like scans:

```python
# The MCP client handles this with configurable timeout
# NUBICUSTOS_MCP_REQUEST_TIMEOUT=120 for long scans

Claude Response Pattern:
"The scan is taking longer than expected. I'll check the status..."
[Uses get_scan_status() to poll for completion]
```

### Graceful Degradation

When some services are unavailable:

```
User: "Show me the asset graph"
Error: Neo4j unavailable

Claude Response Pattern:
"The Neo4j graph database is currently unavailable, but I can still provide
security findings from PostgreSQL. Here's what I found..."
[Falls back to search_findings() and attack path analysis from PostgreSQL]
```

---

## End-to-End Examples

### Example 1: Complete Security Audit

**User Request:** "Run a complete security audit of our AWS environment and summarize the results"

**Claude Workflow:**

```
Step 1: Pre-flight check
Claude: "Let me verify the system is ready for scanning..."
[Uses check_health(detailed=True)]
[Uses verify_credentials(provider="aws")]

Step 2: Start scan
Claude: "Starting comprehensive AWS security scan. This typically takes 30-50 minutes..."
[Uses trigger_scan(profile="comprehensive")]
Scan ID: abc123

Step 3: Monitor progress
Claude: "Scan in progress. I'll check status periodically..."
[Polls get_scan_status("abc123") every 2 minutes]
"Progress: 45 findings discovered so far (3 critical, 12 high)..."

Step 4: Analyze results
Claude: "Scan complete. Analyzing results..."
[Uses get_findings_summary()]
[Uses list_attack_paths(min_risk_score=70)]

Step 5: Generate summary
Claude: "Here's the executive summary:

**Security Audit Results - AWS Environment**

Scan completed: [timestamp]
Duration: 42 minutes

**Finding Summary:**
- Critical: 5 (action required immediately)
- High: 23 (address within 7 days)
- Medium: 67 (address within 30 days)
- Low: 45 (scheduled maintenance)

**Top Risks:**
1. Root account without MFA (Critical)
2. Public S3 bucket with sensitive data (Critical)
3. Overly permissive IAM role (High)

**Attack Paths Discovered:** 8
- 3 paths lead to potential account takeover
- 2 paths enable data exfiltration

**Recommended Actions:**
1. Enable MFA on root account immediately
2. Review and restrict S3 bucket policies
3. Implement least-privilege IAM policies

Would you like me to dive deeper into any of these findings?"
```

### Example 2: Incident Response Triage

**User Request:** "We suspect a security incident. Help me investigate unusual IAM activity."

**Claude Workflow:**

```
Step 1: Gather IAM findings
Claude: "I'll check for IAM-related security findings..."
[Uses search_findings(resource_type="iam", severity="critical,high")]

Step 2: Check for credential exposure
Claude: "Checking for exposed credentials..."
[Uses get_exposed_credentials()]

Step 3: Analyze privilege escalation paths
Claude: "Analyzing privilege escalation risks..."
[Uses list_privesc_paths(min_risk_score=60)]

Step 4: Check assumed roles
Claude: "Reviewing role assumption patterns..."
[Uses run_cloudfox(module_name="assumed-roles")]

Step 5: Provide analysis
Claude: "**IAM Security Analysis**

**Immediate Concerns:**
- Found 2 IAM users with programmatic access and no activity in 90+ days
- 1 role allows assumption from any AWS account
- 3 policies grant admin-level access unnecessarily

**Credential Status:**
- No active exposed credentials found in code repos
- 1 historical credential exposure (already rotated)

**Privilege Escalation Paths:**
- Found 4 paths from current IAM configuration
- Most critical: User 'developer-jenkins' can escalate to admin via Lambda

**Recommendations:**
1. Revoke access for inactive users
2. Restrict role trust policies
3. Implement permission boundaries
4. Enable CloudTrail alerts for IAM changes

Would you like me to generate remediation commands for any of these?"
```

### Example 3: Compliance Gap Analysis

**User Request:** "How compliant are we with CIS AWS Foundations Benchmark?"

**Claude Workflow:**

```
Step 1: Run compliance-focused scan
Claude: "Running CIS benchmark compliance scan..."
[Uses trigger_scan(profile="compliance-only")]

Step 2: Wait for completion
[Polls scan status until complete]

Step 3: Analyze compliance findings
Claude: "Analyzing CIS benchmark compliance..."
[Uses search_findings(cloud_provider="aws")]
[Filters for CIS-related compliance mappings]

Step 4: Generate compliance report
Claude: "**CIS AWS Foundations Benchmark v2.0 - Compliance Report**

**Overall Compliance Score: 72%**

**Section Breakdown:**

| Section | Passed | Failed | Score |
|---------|--------|--------|-------|
| 1. IAM | 15 | 7 | 68% |
| 2. Storage | 8 | 3 | 73% |
| 3. Logging | 12 | 2 | 86% |
| 4. Monitoring | 6 | 4 | 60% |
| 5. Networking | 10 | 2 | 83% |

**Critical Gaps:**
1. [1.4] Root account MFA not enabled
2. [1.14] IAM access analyzer not enabled in all regions
3. [2.1.1] S3 bucket encryption not enforced
4. [4.3] CloudWatch log metric filters not configured

**Quick Wins (Easy to Fix):**
- Enable S3 default encryption: 5 minutes
- Enable IAM Access Analyzer: 10 minutes
- Add CloudWatch log groups: 15 minutes

Would you like remediation steps for specific controls?"
```

### Example 4: Automated Daily Security Check

**User Request:** "Do a quick daily security check and alert me to any new critical issues"

**Claude Workflow:**

```
Step 1: Run quick scan
Claude: "Running quick security check (critical/high only)..."
[Uses trigger_scan(profile="quick")]

Step 2: Compare with baseline
[Uses get_findings_summary()]
[Uses list_scans() to get previous scan for comparison]

Step 3: Identify new findings
Claude: "**Daily Security Check - [Date]**

**New Findings Since Yesterday:**
- Critical: 1 new (up from 4 to 5 total)
- High: 3 new (up from 20 to 23 total)

**NEW Critical Finding:**
[CIS 1.4] Root account MFA was disabled at 3:42 AM
- Resource: AWS Account 123456789012
- First seen: Today at 03:42:00 UTC
- Action required: Immediate

**NEW High Findings:**
1. Security group opened port 22 to 0.0.0.0/0
2. IAM user created without MFA requirement
3. S3 bucket policy allows public access

**Resolved Since Yesterday:**
- 2 medium findings marked as mitigated

**Attack Surface:**
- No change in public exposures
- No new credential leaks detected

Would you like me to create JIRA tickets for the new findings?"
```

### Example 5: Resource-Focused Investigation

**User Request:** "What security issues affect our payment processing infrastructure?"

**Claude Workflow:**

```
Step 1: Search for related resources
Claude: "Searching for payment-related resources..."
[Uses search_findings(search="payment")]
[Uses search_findings(search="pci")]
[Uses search_findings(search="card")]

Step 2: Analyze attack paths
Claude: "Checking attack paths to payment systems..."
[Uses list_attack_paths(target_type="data_exfiltration")]

Step 3: Check compliance
[Filters findings with PCI-DSS compliance mappings]

Step 4: Generate focused report
Claude: "**Payment Infrastructure Security Assessment**

**Resources Identified:**
- 3 EC2 instances (payment-api-1, payment-api-2, payment-processor)
- 2 RDS instances (payment-db-primary, payment-db-replica)
- 1 S3 bucket (payment-audit-logs)
- 4 Lambda functions (payment-*)

**Security Findings:**
| Severity | Count | Top Issue |
|----------|-------|-----------|
| Critical | 0 | - |
| High | 2 | RDS not using encryption at rest |
| Medium | 5 | Missing detailed CloudTrail logging |
| Low | 3 | Instance metadata v2 not enforced |

**PCI-DSS Compliance:**
- Requirement 3 (Protect stored data): 2 gaps
- Requirement 8 (Access control): 1 gap
- Requirement 10 (Logging): 3 gaps

**Attack Paths:**
Found 1 path that could reach payment database:
Entry: Public-facing payment-api-1
Path: API -> Lambda -> RDS (via overly permissive IAM role)
Risk Score: 65/100

**Recommendations:**
1. Enable RDS encryption (requires maintenance window)
2. Tighten Lambda execution role permissions
3. Enable IMDSv2 on all payment instances
4. Add VPC flow logs for payment subnet

Shall I provide remediation commands for the RDS encryption?"
```

---

## Tips for Effective Use

### Best Practices

1. **Start with health checks** - Always verify connectivity before complex operations
2. **Use appropriate scan profiles** - Quick for daily checks, comprehensive for audits
3. **Leverage filtering** - Use severity and status filters to focus on actionable items
4. **Track remediation** - Update finding status as issues are addressed
5. **Compare over time** - Use scan comparison to track security posture trends

### Performance Tips

1. **Pagination** - Use page_size for large result sets to avoid timeouts
2. **Filtering** - Apply filters server-side rather than fetching all data
3. **Caching** - The MCP server caches health checks for 15 minutes
4. **Async operations** - Scans run asynchronously; poll status instead of waiting

### Security Considerations

1. **API keys** - Use environment variables, never hardcode in config
2. **Network access** - Restrict API access to trusted networks
3. **Audit logging** - All MCP operations are logged via the API
4. **Credential handling** - MCP server never sees cloud credentials directly
