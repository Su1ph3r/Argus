# Nubicustos MCP Server

MCP (Model Context Protocol) server for interacting with the Nubicustos cloud security auditing platform. Enables local LLMs to query findings, trigger scans, analyze attack paths, and generate security reports.

## Requirements

- Python 3.11+
- Running Nubicustos stack (`docker-compose up -d` in the main project)
- MCP-compatible client (Claude Desktop, Ollama, LM Studio, etc.)

## Installation

### From Source

```bash
cd nubicustos-mcp
pip install -e .
```

### With Development Dependencies

```bash
pip install -e ".[dev]"
```

## Configuration

The MCP server connects to the Nubicustos REST API. Configure via environment variables:

```bash
# Required: Nubicustos API URL
export NUBICUSTOS_MCP_API_URL=http://localhost:8000

# Optional: API key if authentication is enabled
export NUBICUSTOS_MCP_API_KEY=your-api-key
```

Or create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your settings
```

## Usage

### With Claude Desktop

Add to your Claude Desktop config (`~/.config/claude/config.json` on Linux/Mac or `%APPDATA%\Claude\config.json` on Windows):

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

### With Ollama / LM Studio

Run the MCP server in stdio mode:

```bash
python -m nubicustos_mcp.server
```

The server communicates via stdin/stdout using the MCP protocol.

### Standalone Testing

```bash
# Check if the server starts correctly
python -c "from nubicustos_mcp.server import mcp; print('Server initialized')"
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
| `get_attack_path_details` | Get full attack path |
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

### Compliance Review

```
User: Are we compliant with CIS?
Assistant: [Uses compliance_gap_analysis prompt]
```

## Development

### Running Tests

```bash
pytest
```

### Code Style

The project uses standard Python formatting. Run linting with:

```bash
ruff check src/
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
│   └── prompts/       # MCP prompt templates
└── pyproject.toml     # Package configuration
```

The server wraps the Nubicustos REST API running at `http://localhost:8000`. It does not access the database directly - all operations go through the API.

## Troubleshooting

### Connection Refused

Ensure the Nubicustos stack is running:

```bash
cd /path/to/Cloud-Stack
docker-compose up -d
curl http://localhost:8000/api/health
```

### Invalid Credentials

Check your cloud provider credentials:

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

## License

MIT
