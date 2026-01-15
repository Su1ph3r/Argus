# Error Tracking

> Added in v1.0.2

Nubicustos provides per-tool error tracking to help diagnose scan failures and understand which security tools succeeded or failed.

## Overview

When a scan runs multiple security tools, each tool may succeed, fail, or encounter errors independently. The error tracking system:
- Records per-tool execution status
- Captures error messages for failed tools
- Provides detailed error breakdown via API
- Shows error dialogs in the web UI

## Understanding Tool Exit Codes

Security scanning tools use various exit codes:

| Exit Code | Meaning | Scan Status |
|-----------|---------|-------------|
| 0 | Success, no findings | Completed |
| 1 | Success, findings detected | Completed |
| 3 | Success, findings + non-critical errors (Prowler) | Completed |
| Other | Actual failure | Failed/Partial |

**Important**: Exit codes 1 and 3 are typically **success** indicators for security tools - they mean the tool found security issues, which is expected behavior.

## Web UI Error Dialog

When viewing scan details (`/scans/:id`):

1. If any tools failed, an error indicator appears
2. Click the error indicator to open the **Error Details Dialog**
3. Dialog shows:
   - List of all tools executed
   - Status of each tool (success/failed)
   - Error message for failed tools
   - Timestamp of failure

### Error Dialog Contents

```
┌─────────────────────────────────────────┐
│  Scan Error Details                     │
├─────────────────────────────────────────┤
│  Tool          │ Status  │ Error        │
│────────────────┼─────────┼──────────────│
│  prowler       │ ✓ OK    │ -            │
│  scoutsuite    │ ✗ Failed│ Timeout      │
│  cloudfox      │ ✓ OK    │ -            │
│  cloudsploit   │ ✗ Failed│ Auth error   │
├─────────────────────────────────────────┤
│  2 of 4 tools failed                    │
└─────────────────────────────────────────┘
```

## API Endpoint

### Get Per-Tool Errors

```bash
curl http://localhost:8000/api/scans/{scan_id}/errors
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_errors": {
    "prowler": null,
    "scoutsuite": "Connection timeout after 300s",
    "cloudfox": null,
    "cloudsploit": "Authentication failed: invalid credentials"
  },
  "total_tools": 4,
  "failed_tools": 2,
  "success_tools": 2
}
```

**Field explanations:**
- `tool_errors`: Map of tool name to error message (null = success)
- `total_tools`: Number of tools that were executed
- `failed_tools`: Count of tools that failed
- `success_tools`: Count of tools that succeeded

## Common Error Causes

### Authentication Errors
```
"Authentication failed: invalid credentials"
"AWS credentials expired"
"No valid credentials found"
```

**Solution**: Check credential configuration in `/credentials` page or refresh AWS tokens.

### Timeout Errors
```
"Connection timeout after 300s"
"Tool execution timed out"
```

**Solution**:
- Check network connectivity
- Increase timeout in scan profile
- Reduce scan scope

### Container Errors
```
"Container exited with code 137"
"OOM killed"
```

**Solution**: Increase Docker memory limits or reduce concurrent tools.

### Permission Errors
```
"Access denied to resource"
"Insufficient IAM permissions"
```

**Solution**: Review IAM policy for the scanning role. See [[AWS Security Analysis|AWS-Security-Analysis]].

## Log Sanitization

Error messages are automatically sanitized to prevent information leakage:
- AWS access keys are redacted
- Passwords and tokens are masked
- IP addresses are partially hidden
- Account IDs are preserved for debugging

Example:
```
Original: "Failed to connect to 192.168.1.100 with key AKIA1234567890ABCDEF"
Sanitized: "Failed to connect to 192.168.x.x with key AKIA****CDEF"
```

## Troubleshooting Failed Scans

### Step 1: Check Error Breakdown
```bash
curl http://localhost:8000/api/scans/{scan_id}/errors | jq
```

### Step 2: Review Tool Logs
```bash
# Check container logs for failed tool
docker logs security-{tool_name}-{scan_id}
```

### Step 3: Verify Credentials
```bash
# Test AWS credentials
aws sts get-caller-identity --profile {profile_name}
```

### Step 4: Check Tool Configuration
Review tool-specific settings in the scan profile.

### Step 5: Retry Individual Tool
```bash
# Trigger single-tool scan for debugging
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "tools": ["prowler"]}'
```

## Error Handling Best Practices

1. **Monitor partial failures**: A scan with some failed tools may still provide useful findings
2. **Check expected exit codes**: Don't assume exit code 1 means failure
3. **Review error patterns**: Repeated timeout errors may indicate infrastructure issues
4. **Use dry-run first**: Test scan configuration before full execution

---

*See also: [[Scan Orchestration|Scan-Orchestration]], [[REST API Overview|API]], [[Web Frontend|Web-Frontend]]*
