# MCP Server Integration

The Nubicustos MCP (Model Context Protocol) server enables integration with LLMs for AI-assisted security analysis. Query findings, trigger scans, and analyze attack paths using natural language.

## Overview

The MCP server wraps the Nubicustos REST API and exposes:
- **27+ Tools** for querying and triggering operations
- **6 Resources** for accessing security data
- **8+ Prompts** for analysis workflows

## Installation

```bash
cd nubicustos-mcp
pip install -e .
```

With development dependencies:
```bash
pip install -e ".[dev]"
```

## Configuration

Set environment variables:
```bash
export NUBICUSTOS_MCP_API_URL=http://localhost:8000
export NUBICUSTOS_MCP_API_KEY=your-api-key  # Optional
```

Or create a `.env` file:
```bash
NUBICUSTOS_MCP_API_URL=http://localhost:8000
NUBICUSTOS_MCP_API_KEY=your-api-key
```

## Client Configuration

### Claude Desktop

Add to `~/.config/claude/config.json` (Linux/Mac) or `%APPDATA%\Claude\config.json` (Windows):

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

### Ollama / LM Studio

Run the MCP server in stdio mode:
```bash
python -m nubicustos_mcp.server
```

## Available Tools

### Scan Management

| Tool | Description |
|------|-------------|
| `list_scans` | List security scans with filters |
| `trigger_scan` | Start a new security scan |
| `get_scan_status` | Get scan status and finding counts |
| `cancel_scan` | Cancel a running scan |
| `list_scan_profiles` | List available scan profiles |

### Finding Queries

| Tool | Description |
|------|-------------|
| `search_findings` | Search findings with filters |
| `get_findings_summary` | Get aggregated statistics |
| `get_finding_details` | Get full finding details |
| `update_finding_status` | Update finding status |

### Attack Paths & Security

| Tool | Description |
|------|-------------|
| `list_attack_paths` | List discovered attack paths |
| `get_attack_path_details` | Get full attack path with nodes/edges |
| `analyze_attack_paths` | Trigger path analysis |
| `list_privesc_paths` | List privilege escalation paths |
| `get_public_exposures` | List public exposures |
| `get_exposed_credentials` | List credential leaks |

### Cloud-Specific

| Tool | Description |
|------|-------------|
| `get_imds_checks` | EC2 metadata vulnerabilities |
| `get_lambda_analysis` | Lambda security issues |
| `run_cloudfox` | Run CloudFox enumeration |
| `run_enumerate_iam` | Enumerate IAM permissions |

### Exports & System

| Tool | Description |
|------|-------------|
| `export_findings` | Export findings as CSV/JSON |
| `get_export_summary` | Get export statistics |
| `check_health` | Check API health |
| `get_sync_status` | Get database sync status |
| `verify_credentials` | Verify cloud credentials |

## Available Resources

| URI | Description |
|-----|-------------|
| `nubicustos://summary` | Security posture summary |
| `nubicustos://profiles` | Available scan profiles |
| `nubicustos://tools` | Scanning tools info |
| `nubicustos://settings` | Current settings |
| `nubicustos://scans/{id}` | Specific scan details |
| `nubicustos://findings/{severity}` | Findings by severity |

## Available Prompts

### Scan Execution
- `run_quick_scan` - Quick 5-10 minute scan
- `run_full_audit` - Comprehensive 30-60 minute audit
- `run_aws_scan` - AWS-focused scan
- `run_kubernetes_scan` - Kubernetes-focused scan
- `run_iac_scan` - Infrastructure-as-Code scan
- `run_compliance_scan` - Compliance-focused scan

### Analysis
- `analyze_security_posture` - Overall risk assessment
- `triage_finding` - Finding triage recommendation
- `explain_attack_path` - Business-friendly explanation
- `compliance_gap_analysis` - Framework compliance gaps
- `investigate_resource` - Resource security profile
- `analyze_iam_risks` - IAM privilege escalation analysis
- `analyze_public_exposure` - Attack surface review
- `analyze_lambda_security` - Serverless security review

### Operations
- `pre_scan_check` - Pre-scan readiness check
- `compare_scans` - Compare scan results
- `create_remediation_plan` - Prioritized remediation
- `summarize_scan_results` - Executive summary

## Example Conversations

### Quick Security Check
```
User: Check my AWS security posture
Assistant: [Uses pre_scan_check prompt, then trigger_scan with quick profile]
```

### Finding Investigation
```
User: What's wrong with finding 123?
Assistant: [Uses get_finding_details and triage_finding prompt]
```

### Attack Path Analysis
```
User: Show me the most critical attack paths
Assistant: [Uses list_attack_paths sorted by impact, then explain_attack_path]
```

### Compliance Review
```
User: Are we compliant with CIS?
Assistant: [Uses compliance_gap_analysis prompt]
```

## Architecture

```
nubicustos-mcp/
├── src/nubicustos_mcp/
│   ├── server.py      # FastMCP server instance
│   ├── config.py      # Pydantic settings
│   ├── client.py      # Async HTTP client
│   ├── tools/         # MCP tool implementations
│   ├── resources/     # MCP resource implementations
│   └── prompts/       # LLM prompt templates
└── pyproject.toml     # Package configuration
```

The server communicates with the Nubicustos REST API at `http://localhost:8000`. It does not access databases directly.

## Troubleshooting

### Connection Refused
Ensure the Nubicustos stack is running:
```bash
docker-compose up -d
curl http://localhost:8000/api/health
```

### Invalid Credentials
Check cloud provider credentials:
```bash
# Using the MCP tool
verify_credentials(provider="aws")
```

### Scan Not Starting
Verify system health:
```bash
# Using the MCP tool
check_health(detailed=True)
```

---

*See also: [[REST API Overview|API]], [[Scan Orchestration|Scan-Orchestration]]*
