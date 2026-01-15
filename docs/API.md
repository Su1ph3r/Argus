# Nubicustos API Reference

This document provides a complete reference for the Nubicustos REST API.

## Base URL

```
http://localhost:8000/api
```

## Authentication

The API supports optional API key authentication. When enabled, include the key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/findings
```

To enable authentication, set `API_KEY` in your `.env` file.

---

## Health Endpoints

### GET /health

Basic health check for load balancers.

**Response:**
```json
{
  "status": "healthy",
  "database": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

### GET /health/detailed

Detailed health check with all service statuses.

**Response:**
```json
{
  "status": "healthy",
  "services": [
    {"name": "postgresql", "status": "healthy", "message": null, "latency_ms": 1.5},
    {"name": "neo4j", "status": "healthy", "message": "Connection successful", "latency_ms": 12.3},
    {"name": "database_tables", "status": "healthy", "message": "All core tables accessible"}
  ],
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime_seconds": 3600.5
}
```

### GET /health/live

Kubernetes liveness probe. Returns 200 if API is running.

### GET /health/ready

Kubernetes readiness probe. Checks all critical dependencies.

---

## Scans Endpoints

### GET /scans

List all scans with optional filters and pagination.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| status | string | Filter by status (pending, running, completed, failed) |
| tool | string | Filter by tool name |
| page | int | Page number (default: 1) |
| page_size | int | Items per page (1-100, default: 20) |

**Example Request:**
```bash
curl "http://localhost:8000/api/scans?status=completed&page=1&page_size=10"
```

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "scan_type": "comprehensive",
      "target": "all",
      "tool": "multi-tool",
      "status": "completed",
      "started_at": "2024-01-15T10:00:00Z",
      "completed_at": "2024-01-15T10:45:00Z",
      "total_findings": 127,
      "critical_findings": 5,
      "high_findings": 23,
      "medium_findings": 45,
      "low_findings": 54
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 10
}
```

### POST /scans

Trigger a new security scan.

**Request Body:**
```json
{
  "profile": "quick",
  "aws_profile": "default",
  "target": "all",
  "severity_filter": "critical,high",
  "dry_run": false
}
```

**Parameters:**
- `profile` - Scan profile: `quick`, `comprehensive`, or `compliance-only`
- `aws_profile` - AWS credential profile name (v1.0.2)
- `target` - Scan target (default: "all")
- `severity_filter` - Filter by severity levels
- `dry_run` - Preview mode without execution

**Profiles:**
- `quick` - Fast scan (5-10 min), critical/high issues only
- `comprehensive` - Full audit (30-60 min), all tools enabled
- `compliance-only` - Compliance-focused scanning (15-20 min)

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_type": "quick",
  "status": "running",
  "started_at": "2024-01-15T10:30:00Z"
}
```

### GET /scans/{scan_id}

Get details of a specific scan.

### GET /scans/{scan_id}/status

Get lightweight status for polling scan progress.

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "total_findings": 45,
  "critical_findings": 2,
  "high_findings": 8,
  "medium_findings": 20,
  "low_findings": 15
}
```

### DELETE /scans/{scan_id}

Cancel a running or pending scan.

### GET /scans/profiles/list

List available scan profiles with descriptions.

### GET /scans/{scan_id}/errors

Get per-tool error breakdown for a scan. (v1.0.2)

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_errors": {
    "prowler": null,
    "scoutsuite": "Connection timeout after 300s",
    "cloudfox": null
  },
  "total_tools": 3,
  "failed_tools": 1
}
```

---

## Bulk Operations (v1.0.2)

### DELETE /scans/bulk

Delete multiple scans at once.

**Request Body:**
```json
{
  "scan_ids": ["id1", "id2", "id3"]
}
```

**Response:**
```json
{
  "deleted": 3,
  "failed": [],
  "message": "Successfully deleted 3 scans"
}
```

### POST /scans/bulk/archive

Create a downloadable zip archive of scan reports.

**Request Body:**
```json
{
  "scan_ids": ["id1", "id2"]
}
```

**Response:**
```json
{
  "archive_id": "archive-uuid",
  "filename": "scans_2024-01-15_143022.zip",
  "size_bytes": 1048576,
  "download_url": "/api/scans/archives/archive-uuid/download"
}
```

### GET /scans/archives

List available scan archives.

**Response:**
```json
{
  "archives": [
    {
      "id": "archive-uuid",
      "filename": "scans_2024-01-15_143022.zip",
      "created_at": "2024-01-15T14:30:22Z",
      "size_bytes": 1048576,
      "scan_count": 2
    }
  ]
}
```

### GET /scans/archives/{archive_id}/download

Download an archive file.

**Response:** Binary file download (application/zip)

### DELETE /scans/archives/{archive_id}

Delete an archive.

---

## Findings Endpoints

### GET /findings

List findings with comprehensive filtering options.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| search | string | Search in finding titles |
| severity | string | Comma-separated: critical,high,medium,low |
| status | string | Comma-separated: open,closed,mitigated,accepted,fail (default: open,fail) |
| cloud_provider | string | aws, azure, gcp, kubernetes |
| tool | string | prowler, scoutsuite, kubescape, etc. |
| resource_type | string | Filter by resource type |
| scan_id | UUID | Filter by specific scan |
| page | int | Page number (default: 1) |
| page_size | int | Items per page (1-500, default: 50) |

**Example Request:**
```bash
curl "http://localhost:8000/api/findings?severity=critical,high&cloud_provider=aws"
```

**Response:**
```json
{
  "findings": [
    {
      "id": 123,
      "finding_id": "prowler-aws-iam-root-mfa",
      "tool": "prowler",
      "cloud_provider": "aws",
      "severity": "critical",
      "status": "open",
      "title": "Root account does not have MFA enabled",
      "description": "The AWS root account should have MFA enabled...",
      "remediation": "Enable MFA for the root account...",
      "resource_type": "iam.account",
      "resource_id": "123456789012",
      "resource_name": "AWS Account",
      "region": "global",
      "scan_date": "2024-01-15T10:30:00Z",
      "first_seen": "2024-01-10T00:00:00Z",
      "last_seen": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

### GET /findings/summary

Get aggregated finding statistics.

**Response:**
```json
{
  "total": 247,
  "critical": 5,
  "high": 23,
  "medium": 145,
  "low": 74,
  "info": 0,
  "by_provider": {
    "aws": 150,
    "kubernetes": 97
  },
  "by_tool": {
    "prowler": 100,
    "kubescape": 97,
    "scoutsuite": 50
  }
}
```

### GET /findings/{finding_id}

Get complete finding details including aggregated tool sources and affected resources.

### PATCH /findings/{finding_id}

Update a finding's status or tags.

**Request Body:**
```json
{
  "status": "mitigated",
  "tags": {
    "ticket": "JIRA-123",
    "owner": "security-team"
  }
}
```

**Valid Statuses:**
- `open` - Active finding requiring attention
- `closed` - Resolved finding
- `mitigated` - Risk has been reduced
- `accepted` - Risk accepted with justification
- `false_positive` - Incorrectly reported issue

### GET /findings/by-resource/{resource_id}

Get all findings for a specific resource.

---

## Attack Paths Endpoints

### GET /attack-paths

List discovered attack paths with filters.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| min_risk_score | int | Minimum risk score (0-100) |
| max_risk_score | int | Maximum risk score (0-100) |
| exploitability | string | confirmed, likely, theoretical |
| entry_point_type | string | public_s3, public_ec2, etc. |
| target_type | string | account_takeover, data_exfiltration, etc. |
| scan_id | UUID | Filter by specific scan |
| page | int | Page number |
| page_size | int | Items per page (1-100) |

**Response:**
```json
{
  "paths": [
    {
      "id": 1,
      "path_id": "a1b2c3d4e5f67890",
      "name": "Public S3 -> Data Exfiltration",
      "description": "Attack path from public S3 bucket leading to data exfiltration",
      "entry_point_type": "public_s3",
      "entry_point_name": "Public S3 Bucket",
      "target_type": "data_exfiltration",
      "target_description": "Sensitive data theft",
      "risk_score": 85,
      "exploitability": "confirmed",
      "impact": "high",
      "hop_count": 2,
      "requires_authentication": false,
      "poc_available": true,
      "mitre_tactics": ["initial-access", "collection", "exfiltration"],
      "aws_services": ["s3"]
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

### GET /attack-paths/summary

Get attack path statistics.

**Response:**
```json
{
  "total_paths": 15,
  "critical_paths": 3,
  "high_risk_paths": 5,
  "medium_risk_paths": 4,
  "low_risk_paths": 3,
  "entry_point_types": {
    "public_s3": 5,
    "public_ec2": 3,
    "exposed_credentials": 7
  },
  "target_types": {
    "data_exfiltration": 8,
    "privilege_escalation": 4,
    "account_takeover": 3
  },
  "top_mitre_tactics": [
    "initial-access",
    "privilege-escalation",
    "credential-access"
  ],
  "avg_risk_score": 62.5
}
```

### POST /attack-paths/analyze

Trigger attack path analysis.

**Request Body:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{
  "paths_discovered": 15,
  "analysis_time_ms": 2500,
  "summary": {
    "total_paths": 15,
    "critical_paths": 3,
    "high_risk_paths": 5
  }
}
```

### GET /attack-paths/{path_id}

Get complete attack path details.

### GET /attack-paths/{path_id}/findings

Get all findings associated with an attack path.

### GET /attack-paths/{path_id}/export

Export attack path in markdown or JSON format.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| format | string | markdown or json (default: markdown) |

### DELETE /attack-paths/{path_id}

Delete an attack path.

---

## Exports Endpoints

### GET /exports/csv

Export findings as CSV file download.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| severity | string | Comma-separated severity levels |
| status | string | Comma-separated statuses (default: open) |
| cloud_provider | string | Filter by cloud provider |
| include_remediation | bool | Include remediation column (default: true) |

**Example Request:**
```bash
curl "http://localhost:8000/api/exports/csv?severity=critical,high" -o findings.csv
```

### GET /exports/json

Export findings as JSON file download.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| severity | string | Comma-separated severity levels |
| status | string | Comma-separated statuses |
| cloud_provider | string | Filter by cloud provider |

### POST /exports/generate

Generate an export with metadata.

**Request Body:**
```json
{
  "format": "csv",
  "severity_filter": ["critical", "high"],
  "status_filter": ["open"],
  "cloud_provider": "aws"
}
```

### GET /exports/summary

Get export-ready summary statistics.

---

## Error Responses

All endpoints return standard error responses:

```json
{
  "detail": "Error message describing the issue"
}
```

**Common HTTP Status Codes:**
| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid or missing API key |
| 404 | Not Found - Resource does not exist |
| 500 | Internal Server Error |

---

## Rate Limiting

The API does not currently implement rate limiting. For production deployments, consider adding rate limiting at the reverse proxy level (Nginx).

---

## OpenAPI Schema

The complete OpenAPI schema is available at:

```
http://localhost:8000/openapi.json
```

Interactive API documentation (Swagger UI):

```
http://localhost:8000/docs
```

Alternative documentation (ReDoc):

```
http://localhost:8000/redoc
```
