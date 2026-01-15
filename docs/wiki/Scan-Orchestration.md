# Scan Orchestration System

This document provides detailed documentation of the Nubicustos scan orchestration system, which manages the execution of security scanning tools via Docker containers.

## Architecture Overview

The scan orchestration system uses the Docker SDK for Python to manage security tool containers directly, replacing the previous subprocess-based approach for improved reliability and control.

```
┌─────────────────────────────────────────────────────────────────┐
│                        REST API Layer                            │
│                    (FastAPI - scans.py)                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Scan Orchestration                            │
│              (run_scan_orchestration async task)                │
│                                                                  │
│  1. Load scan profile configuration                             │
│  2. For each tool in profile:                                   │
│     a. Build command with profile options                       │
│     b. Start container via DockerExecutor                       │
│     c. Poll for completion (every 10 seconds)                   │
│     d. Check exit code against expected codes                   │
│  3. Trigger report processing                                   │
│  4. Update scan status in database                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Docker Executor                             │
│              (docker_executor.py - DockerExecutor)              │
│                                                                  │
│  - Container lifecycle management                               │
│  - Volume mounting and path resolution                          │
│  - Environment variable configuration                           │
│  - Exit code and log retrieval                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Containers                             │
│                                                                  │
│  ┌─────────┐ ┌───────────┐ ┌──────────┐ ┌───────────────┐      │
│  │ Prowler │ │ ScoutSuite│ │ CloudFox │ │ CloudSploit   │ ...  │
│  └─────────┘ └───────────┘ └──────────┘ └───────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

## Scan Profiles

### Profile Configuration

Profiles are defined in `api/services/docker_executor.py`:

```python
SCAN_PROFILES = {
    "quick": {
        "tools": [ToolType.PROWLER],
        "description": "Fast scan focusing on critical/high severity issues (5-10 min)",
        "duration_estimate": "5-10 minutes",
        "prowler_options": ["--severity", "critical", "high"],
    },
    "comprehensive": {
        "tools": [
            ToolType.PROWLER,
            ToolType.SCOUTSUITE,
            ToolType.CLOUDFOX,
            ToolType.CLOUDSPLOIT,
            ToolType.CLOUD_CUSTODIAN,
            ToolType.CLOUDMAPPER,
            ToolType.CARTOGRAPHY,
        ],
        "description": "Full security audit with all AWS tools (30-60 min)",
        "duration_estimate": "30-60 minutes",
        "prowler_options": [],
    },
    "compliance-only": {
        "tools": [ToolType.PROWLER, ToolType.SCOUTSUITE],
        "description": "Compliance framework focused scanning (15-20 min)",
        "duration_estimate": "15-20 minutes",
        "prowler_options": ["--compliance", "cis_2.0_aws", "soc2_aws", "pci_dss_v4.0_aws"],
        "scoutsuite_options": ["--ruleset", "cis"],
    },
}
```

### Available Profiles

| Profile | Tools | Duration | Use Case |
|---------|-------|----------|----------|
| `quick` | Prowler | 5-10 min | Fast security check, CI/CD integration |
| `comprehensive` | All 7 AWS tools | 30-60 min | Full security audit |
| `compliance-only` | Prowler, ScoutSuite | 15-20 min | Compliance reporting |

## Tool Configuration

### TOOL_CONFIGS Structure

Each tool has a configuration entry:

```python
ToolType.PROWLER: {
    "image": "toniblyx/prowler:4.2.4",
    "container_name_prefix": "prowler-scan",
    "volumes": {
        "/app/reports/prowler": {"bind": "/reports", "mode": "rw"},
        "/app/credentials/aws": {"bind": "/home/prowler/.aws", "mode": "ro"},
    },
    "network": "nubicustos_security-net",
    "environment": {
        "AWS_SHARED_CREDENTIALS_FILE": "/home/prowler/.aws/credentials",
        "AWS_CONFIG_FILE": "/home/prowler/.aws/config",
        "HOME": "/home/prowler",
    },
    "default_command": ["aws", "--output-formats", "json-ocsf", "html", "csv", "--output-directory", "/reports"],
    "expected_exit_codes": [0, 1, 3],
}
```

### Configuration Fields

| Field | Description |
|-------|-------------|
| `image` | Docker image with pinned version |
| `container_name_prefix` | Prefix for container naming |
| `volumes` | Volume mounts (host path → container path) |
| `network` | Docker network for inter-container communication |
| `environment` | Environment variables for the container |
| `default_command` | Default command arguments |
| `expected_exit_codes` | Exit codes that indicate success |
| `entrypoint` | Optional entrypoint override |
| `named_volumes` | Named Docker volumes for persistence |

### Supported Tools

| Tool | Image | Purpose |
|------|-------|---------|
| PROWLER | `toniblyx/prowler:4.2.4` | AWS compliance & security scanning |
| SCOUTSUITE | `opendevsecops/scoutsuite:5.12.0` | Multi-cloud security auditing |
| CLOUDFOX | `bishopfox/cloudfox:1.14.2` | AWS attack surface enumeration |
| CLOUDSPLOIT | `cloudsploit:local` | AWS security configuration scanning |
| CLOUD_CUSTODIAN | `cloudcustodian/c7n:0.9.34` | Policy-as-code enforcement |
| CLOUDMAPPER | `cloudmapper:local` | AWS account visualization |
| CARTOGRAPHY | `ghcr.io/lyft/cartography:0.94.0` | Asset relationship graphing |
| PACU | `rhinosecuritylabs/pacu:1.6.0` | AWS exploitation framework |
| ENUMERATE_IAM | `enumerate-iam:local` | IAM permission enumeration |
| KUBESCAPE | `quay.io/armosec/kubescape:v3.0.8` | Kubernetes security scanning |

## Expected Exit Codes

Security scanning tools commonly return non-zero exit codes when findings are detected. This is expected behavior, not a failure:

| Exit Code | Meaning | Tools |
|-----------|---------|-------|
| 0 | No findings / Success | All tools |
| 1 | Findings detected | Prowler, ScoutSuite, CloudFox |
| 3 | Findings + some check errors | Prowler |

The orchestration system checks the actual exit code against the tool's `expected_exit_codes` configuration before determining success or failure.

## Execution Flow

### 1. Scan Creation

```python
POST /api/scans
{
    "profile": "quick",
    "severity_filter": "critical,high",  # Optional
    "dry_run": false
}
```

### 2. Background Orchestration

```python
async def run_scan_orchestration(scan_id, profile, severity_filter, db_url):
    # 1. Load profile configuration
    profile_config = SCAN_PROFILES[profile]
    tools = profile_config["tools"]

    # 2. Execute each tool sequentially
    for tool in tools:
        # Build command with profile options
        command = build_command(tool, profile_config, severity_filter)

        # Start container
        result = await executor.start_execution(
            tool_type=tool,
            command=command,
            environment={"SCAN_ID": scan_id}
        )

        # Poll for completion
        while True:
            status = await executor.get_execution_status(container_id)
            if status["execution_status"] in [COMPLETED, FAILED]:
                break
            await asyncio.sleep(10)

        # Check exit code against expected codes
        if exit_code not in expected_exit_codes:
            mark_scan_failed()
            return

    # 3. Process reports
    await process_scan_reports(scan_id, tools)

    # 4. Mark scan completed
    mark_scan_completed()
```

### 3. Report Processing

After all tools complete, the report processor:
1. Parses tool-specific output formats
2. Normalizes findings to common schema
3. Links findings to the scan ID
4. Updates finding counts in the scan record

## API Endpoints

### List Profiles

```bash
GET /api/scans/profiles/list
```

Response:
```json
{
    "profiles": [
        {
            "name": "quick",
            "description": "Fast scan focusing on critical/high severity issues (5-10 min)",
            "duration_estimate": "5-10 minutes",
            "tools": ["prowler"]
        },
        {
            "name": "comprehensive",
            "description": "Full security audit with all AWS tools (30-60 min)",
            "duration_estimate": "30-60 minutes",
            "tools": ["prowler", "scoutsuite", "cloudfox", "cloudsploit", "cloud-custodian", "cloudmapper", "cartography"]
        },
        {
            "name": "compliance-only",
            "description": "Compliance framework focused scanning - CIS, SOC2, PCI-DSS, HIPAA (15-20 min)",
            "duration_estimate": "15-20 minutes",
            "tools": ["prowler", "scoutsuite"]
        }
    ]
}
```

### Create Scan

```bash
POST /api/scans
Content-Type: application/json

{
    "profile": "comprehensive",
    "aws_profile": "default",
    "severity_filter": "critical,high,medium",
    "dry_run": false
}
```

**Parameters:**
- `profile` - Scan profile to use (required)
- `aws_profile` - AWS credentials profile name (v1.0.2, default: "default")
- `severity_filter` - Comma-separated severity levels to include
- `dry_run` - Preview scan without executing tools

### AWS Profile Selection (v1.0.2)

The `aws_profile` parameter allows selecting which AWS credentials profile to use for the scan. This enables:
- Multi-account scanning from a single deployment
- Role-based access for different environments
- Separation of audit and production credentials

```bash
# Scan using a specific AWS profile
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "aws_profile": "production-audit"}'
```

The profile must exist in the mounted AWS credentials directory (`/app/credentials/aws/credentials`).

### Get Scan Status

```bash
GET /api/scans/{scan_id}/status
```

Response:
```json
{
    "scan_id": "b52207f4-592d-4fa0-9ec7-d142bb62ee6d",
    "status": "completed",
    "started_at": "2026-01-11T23:30:36.245806",
    "completed_at": "2026-01-11T23:33:47.585734",
    "findings": {
        "total": 162,
        "critical": 1,
        "high": 36,
        "medium": 124,
        "low": 1
    }
}
```

## Container Management

### Volume Mounts

All containers mount:
- **Reports directory**: Write access for output files
- **Credentials directory**: Read-only access for cloud credentials

Path resolution handles the mapping from API container paths (`/app/...`) to host paths.

### Network Isolation

All security tools run on the `nubicustos_security-net` bridge network, enabling:
- Communication with the database for direct writes
- Access to Neo4j for Cartography asset mapping
- Isolation from external networks

### Container Naming

Containers are named with the pattern: `{tool}-scan-{execution_id}`

Example: `prowler-scan-5262d09b-24d`

This ensures unique names even with concurrent scans.

## Error Handling

### Tool Failures

If a tool fails (exit code not in expected codes):
1. Scan status is set to "failed"
2. Error message is stored in scan metadata
3. Remaining tools are not executed
4. Container logs are preserved for debugging

### Container Not Found

If a container disappears during polling:
- Status is set to FAILED
- Error message indicates container was not found

### Docker Connection Issues

The DockerExecutor tries multiple connection methods:
1. Unix socket (`/var/run/docker.sock`)
2. Environment-based configuration
3. TCP connection to `localhost:2375`

## Per-Tool Error Tracking (v1.0.2)

When a scan runs multiple tools, each tool's success or failure is tracked independently. This provides granular visibility into which tools succeeded and which failed.

### Get Tool Errors

```bash
GET /api/scans/{scan_id}/errors
```

Response:
```json
{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "tool_errors": {
        "prowler": null,
        "scoutsuite": "Connection timeout after 300s",
        "cloudfox": null
    },
    "total_tools": 3,
    "failed_tools": 1,
    "success_tools": 2
}
```

A `null` value indicates the tool succeeded. String values contain the error message.

For detailed information about error tracking, exit code handling, and troubleshooting failed tools, see [[Error Tracking|Error-Tracking]].

## Orphan Scan Recovery (v1.0.2)

On API startup, the system automatically detects and recovers orphan scans - scans that were running when the API was previously shut down or restarted.

### Recovery Process

1. **Detection**: On startup, queries database for scans with `status = 'running'`
2. **Container Check**: Verifies if scan containers are still running via Docker SDK
3. **Recovery Action**:
   - If container is running: Resumes monitoring the scan
   - If container is gone: Marks scan as `failed` with message "Scan orphaned during API restart"

### Automatic Cleanup

```
[API Start] → [Query Running Scans] → [Check Container Status]
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
              [Container Found]    [Container Gone]        [No Orphans]
                    │                      │                      │
              [Resume Monitor]      [Mark Failed]          [Continue]
```

This ensures scan status accurately reflects reality after any API restart or crash.

## Bulk Operations (v1.0.2)

The scan system supports bulk operations for managing multiple scans:

- **Bulk Delete**: Remove multiple scans in a single API call
- **Bulk Archive**: Create downloadable ZIP archives of scan reports

### Bulk Delete

```bash
DELETE /api/scans/bulk
Content-Type: application/json

{"scan_ids": ["id1", "id2", "id3"]}
```

### Bulk Archive

```bash
POST /api/scans/bulk/archive
Content-Type: application/json

{"scan_ids": ["id1", "id2"]}
```

For complete documentation of bulk operations, archive management, and use cases, see [[Bulk Operations|Bulk-Operations]].

## Best Practices

### For Production Deployments

1. **Set Resource Limits**: Add `mem_limit` and `cpu_quota` to container configs
2. **Configure Timeouts**: Add execution timeout handling for hung containers
3. **Enable API Authentication**: Set `API_KEY` environment variable
4. **Use Specific Image Tags**: Avoid `latest` tags for reproducibility
5. **Monitor Container Logs**: Aggregate logs for troubleshooting

### For CI/CD Integration

```bash
# Trigger quick scan and wait for completion
SCAN_ID=$(curl -s -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick"}' | jq -r '.scan_id')

# Poll until complete
while true; do
  STATUS=$(curl -s http://localhost:8000/api/scans/$SCAN_ID/status | jq -r '.status')
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  sleep 30
done

# Check for critical findings
CRITICAL=$(curl -s http://localhost:8000/api/scans/$SCAN_ID/status | jq '.findings.critical')
if [ "$CRITICAL" -gt 0 ]; then
  echo "Critical findings detected!"
  exit 1
fi
```

## Troubleshooting

### Scan Stuck in "Running"

1. Check container status: `docker ps | grep scan`
2. Check container logs: `docker logs {container_name}`
3. Check API logs: `docker logs security-api`

### Exit Code Errors

If scans fail with unexpected exit codes:
1. Check the tool's documentation for exit code meanings
2. Update `expected_exit_codes` in TOOL_CONFIGS if appropriate
3. Review container logs for actual errors

### Volume Mount Issues

If tools can't access credentials or write reports:
1. Verify `HOST_REPORTS_PATH` is set correctly
2. Check directory permissions on the host
3. Ensure the Docker socket is accessible

---

*For more information, see the [[API Reference|API]] and [[Architecture Overview|ARCHITECTURE]].*
