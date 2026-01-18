# Nubicustos Phase 1 Features

This document describes the Open Source features added in Phase 1.

## Overview

Phase 1 adds 5 major features with **zero breaking changes** to existing functionality:

1. **Intelligent Alert Prioritization** - Enhanced risk scoring with asset criticality
2. **Threat Intelligence Enrichment** - Extensible provider framework (design)
3. **Scheduled Scanning** - Recurring scans with cron/interval support
4. **Slack/Teams Notifications** - Scan completion notifications
5. **Enhanced Dashboard** - Risk trends, tool health, compliance overview

---

## Feature 1: Intelligent Alert Prioritization

### New API Endpoints

#### GET /api/findings/top-critical
Returns the highest-risk findings by risk score.

**Query Parameters:**
- `limit` (int, 1-100, default: 10) - Number of findings to return
- `status` (string, optional) - Comma-separated statuses (default: "open,fail")

**Response:**
```json
{
  "findings": [
    {
      "id": 454,
      "finding_id": "ec2_openallportsprotocols_...",
      "title": "Open All Ports Protocols",
      "severity": "critical",
      "risk_score": 94.6,
      "resource_type": "EC2",
      "resource_id": "arn:aws:ec2:...",
      "cloud_provider": "aws",
      "tool": "cloudsploit",
      "scan_date": "2026-01-17T21:24:05.802934"
    }
  ],
  "total": 10,
  "limit": 10
}
```

#### GET /api/findings/trend
Returns severity trend over time for dashboard charts.

**Query Parameters:**
- `days` (int, 1-365, default: 30) - Days to look back
- `status` (string, optional) - Comma-separated statuses (default: "open,fail")

**Response:**
```json
{
  "trend": [
    {
      "date": "2026-01-17",
      "critical": 2,
      "high": 24,
      "medium": 492,
      "low": 2,
      "info": 0,
      "total": 520
    }
  ],
  "days": 30,
  "start_date": "2025-12-19T00:00:00",
  "end_date": "2026-01-18T00:00:00"
}
```

### Enhanced Risk Scoring

The `calculate_enhanced_risk_score()` function in `report-processor/severity_scoring.py` extends base scoring with:

- **Asset Criticality** - Weights findings based on resource importance (critical: 1.3x, high: 1.15x, medium: 1.0x, low: 0.85x)
- **Blast Radius** - Considers downstream impact (1-100+ resources)
- **Recurrence** - Penalizes repeat findings (up to 1.2x multiplier)

### Database Columns Added

```sql
ALTER TABLE findings ADD COLUMN asset_criticality VARCHAR(16) DEFAULT 'medium';
ALTER TABLE findings ADD COLUMN blast_radius INTEGER DEFAULT 1;
ALTER TABLE findings ADD COLUMN recurrence_count INTEGER DEFAULT 1;
ALTER TABLE findings ADD COLUMN scoring_factors JSONB DEFAULT '{}';
```

---

## Feature 2: Threat Intelligence Enrichment (Design)

### Provider Framework

Located in `report-processor/threat_intel_providers.py`, provides:

- `ThreatIntelProvider` - Abstract base class for provider implementations
- `ThreatIntelResult` - Standardized result dataclass
- `ProviderRegistry` - Registry for managing multiple providers
- `PlaceholderProvider` - Design demonstration (no actual API calls)

### New API Endpoint

#### GET /api/findings/{id}/threat-intel
Returns threat intelligence enrichment data for a finding.

**Response (when not enriched):**
```json
{
  "finding_id": 1,
  "enriched": false,
  "last_checked": null,
  "data": null,
  "message": "Threat intel enrichment not configured.",
  "available_providers": ["placeholder"],
  "design_structure": {
    "provider_name": "string",
    "indicators": [...],
    "risk_score_delta": "float",
    "categories": [...],
    "mitre_techniques": ["T1234"]
  }
}
```

### Future Integrations

The framework supports adding providers like:
- AlienVault OTX
- VirusTotal
- Shodan
- GreyNoise
- AbuseIPDB

---

## Feature 3: Scheduled Scanning

### New API Endpoints

#### GET /api/schedules
List all scan schedules.

#### POST /api/schedules
Create a new schedule.

**Request Body:**
```json
{
  "name": "Daily Quick Scan",
  "profile": "quick",
  "cron_expression": "0 2 * * *",
  "aws_profile": "nubicustos-audit",
  "is_enabled": true
}
```

#### GET /api/schedules/{schedule_id}
Get schedule details.

#### PATCH /api/schedules/{schedule_id}
Update a schedule.

#### DELETE /api/schedules/{schedule_id}
Delete a schedule.

#### POST /api/schedules/{schedule_id}/trigger
Trigger a scheduled scan immediately.

#### GET /api/schedules/status
Get scheduler status and job list.

**Response:**
```json
{
  "running": true,
  "job_count": 1,
  "jobs": [
    {
      "id": "3054d5b1-397e-430c-bc95-d8f720c748b4",
      "name": "Scan: Daily Quick Scan",
      "next_run": "2026-01-19T02:00:00+00:00"
    }
  ]
}
```

### Schedule Types

- **cron** - Standard 5-field cron expression (minute hour day month day_of_week)
- **interval** - Run every N minutes (minimum 5 minutes)

### Database Table

```sql
CREATE TABLE scan_schedules (
    id SERIAL PRIMARY KEY,
    schedule_id UUID UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    profile VARCHAR(64) NOT NULL,
    schedule_type VARCHAR(32) DEFAULT 'cron',
    cron_expression VARCHAR(128),
    interval_minutes INTEGER,
    next_run_at TIMESTAMP,
    last_run_at TIMESTAMP,
    is_enabled BOOLEAN DEFAULT TRUE,
    ...
);
```

---

## Feature 4: Slack/Teams Notifications

### Configuration

Enable notifications via the Settings API:

```bash
# Enable notifications
curl -X PUT http://localhost:8000/api/settings/notifications_enabled \
  -H "Content-Type: application/json" \
  -d '{"value": true}'

# Set Slack webhook
curl -X PUT http://localhost:8000/api/settings/slack_webhook_url \
  -H "Content-Type: application/json" \
  -d '{"value": "https://hooks.slack.com/services/..."}'

# Set Teams webhook
curl -X PUT http://localhost:8000/api/settings/teams_webhook_url \
  -H "Content-Type: application/json" \
  -d '{"value": "https://outlook.office.com/webhook/..."}'
```

### Notification Content

Notifications are sent on scan completion with:
- Total findings count
- Breakdown by severity (critical, high, medium, low)
- Scan ID for reference

### Non-Fatal Design

Notification failures do NOT affect scan completion. Errors are logged but scans complete successfully.

---

## Feature 5: Enhanced Dashboard

### New API Endpoint

#### GET /api/executions/health/summary
Returns tool execution health statistics.

**Query Parameters:**
- `days` (int, 1-365, default: 30) - Days to look back

**Response:**
```json
{
  "period_days": 30,
  "overall_success_rate": 100,
  "total_executions": 15,
  "tools": {
    "prowler": {
      "tool_name": "prowler",
      "total_executions": 5,
      "completed": 5,
      "failed": 0,
      "success_rate": 100,
      "avg_duration_seconds": 180.5
    }
  }
}
```

### New Vue Components

1. **RiskTrendChart.vue** - Bar chart showing severity trend over time
2. **ToolHealthCard.vue** - Grid displaying tool execution health
3. **ComplianceOverview.vue** - Framework compliance cards with percentages

---

## Migration

Apply the database migration:

```bash
docker exec -i postgresql psql -U auditor -d security_audits < db-migrations/001_phase1_features.sql
```

Rebuild the API container:

```bash
docker compose build api && docker compose up -d api
```

---

## Non-Breaking Guarantees

All Phase 1 changes are **additive**:

- No existing API signatures modified
- No existing response formats changed
- All new database columns have sensible defaults
- Scheduler/notification failures are non-fatal
- All existing functionality preserved
