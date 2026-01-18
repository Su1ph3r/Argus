# Changelog

All notable changes to Nubicustos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.0.3] - 2026-01-18

### Added

#### Phase 1: Open Source Features

##### Intelligent Alert Prioritization
- Enhanced risk scoring with asset criticality multipliers (critical: 1.3x, high: 1.15x, medium: 1.0x, low: 0.85x)
- Blast radius scoring for downstream impact assessment (1-100+ resources)
- Recurrence penalty for repeat findings (up to 1.2x multiplier)
- New API endpoint: `GET /api/findings/top-critical` - Returns highest-risk findings by score
- New API endpoint: `GET /api/findings/trend` - Returns severity trend over time for dashboard charts
- New database columns: `asset_criticality`, `blast_radius`, `recurrence_count`, `scoring_factors`

##### Threat Intelligence Enrichment (Design Framework)
- Extensible provider framework for threat intelligence integrations
- `ThreatIntelProvider` abstract base class for implementing providers
- `ThreatIntelResult` dataclass for standardized enrichment results
- `ProviderRegistry` for managing multiple providers
- `PlaceholderProvider` implementation demonstrating design pattern
- New API endpoint: `GET /api/findings/{id}/threat-intel` - Returns enrichment data structure
- Indicator extraction from findings (IP addresses, domains, hashes)
- Future provider support: AlienVault OTX, VirusTotal, Shodan, GreyNoise, AbuseIPDB

##### Scheduled Scanning
- APScheduler integration for recurring security scans
- Support for cron expressions (5-field standard: minute hour day month day_of_week)
- Support for interval-based schedules (minimum 5 minutes)
- New API endpoints:
  - `GET /api/schedules` - List all schedules
  - `POST /api/schedules` - Create schedule
  - `GET /api/schedules/{id}` - Get schedule details
  - `PATCH /api/schedules/{id}` - Update schedule
  - `DELETE /api/schedules/{id}` - Delete schedule
  - `POST /api/schedules/{id}/trigger` - Trigger immediate execution
  - `GET /api/schedules/status` - Get scheduler status and job list
- New database table: `scan_schedules` with full audit trail
- Automatic schedule loading on API startup
- Non-fatal scheduler failures (API continues if scheduler fails)

##### Slack/Teams Notifications
- Scan completion notifications with findings summary
- Slack webhook integration with formatted messages
- Microsoft Teams webhook integration with adaptive card format
- Unified notification dispatcher supporting multiple channels
- Configuration via Settings API:
  - `PUT /api/settings/notifications_enabled`
  - `PUT /api/settings/slack_webhook_url`
  - `PUT /api/settings/teams_webhook_url`
- Non-fatal notification failures (scan completes even if notification fails)

##### Enhanced Dashboard
- New API endpoint: `GET /api/executions/health/summary` - Tool execution health statistics
- New Vue component: `RiskTrendChart.vue` - Bar chart showing severity trend over time
- New Vue component: `ToolHealthCard.vue` - Grid displaying tool execution health with success rates
- New Vue component: `ComplianceOverview.vue` - Framework compliance cards with percentages
- Dashboard sections for risk trends and tool health monitoring

#### Utilities
- Docker cleanup utility (`scripts/cleanup.sh`) for managing containers, images, and volumes
  - Interactive menu mode for guided cleanup
  - CLI flags: `--containers`, `--images`, `--images-local`, `--volumes`, `--prune`, `--all`
  - Safety features: `--dry-run` preview mode, confirmation prompts, `--force` for automation
  - Warnings before destructive operations (volume deletion)

### Changed
- Dashboard view extended with health and compliance grid sections
- Findings router extended with new endpoint routes (ordered before `/{finding_id}` to avoid conflicts)
- Main application lifespan includes scheduler lifecycle management

### Fixed
- Database session leak in scheduler service (proper try/finally cleanup)
- Private IP detection using `ipaddress` module for accurate RFC 1918 compliance

### Documentation
- Added `docs/PHASE1_FEATURES.md` with comprehensive feature documentation
- API endpoint documentation for all new routes
- Database migration instructions

---

## [1.0.2] - 2025-01-14

### Security
- Fixed path traversal vulnerability with `os.path.realpath()` validation
- Added zip slip prevention in archive creation with arcname validation
- Fixed ReDoS vulnerability with input length limits
- Added log sanitization to redact credentials, tokens, and IP addresses
- Limited validation error details to prevent schema disclosure
- Added specific SQLAlchemyError handling to prevent information leakage
- Added security analysis documenting known considerations for Docker socket access and credential handling
- Input validation maintained for scan profiles and target parameters

### Added

#### Bulk Operations
- Bulk scan operations: multi-select, bulk delete, and bulk archive
- New `scan_files` database table tracking report files per scan
- Archive service for creating downloadable zip files of scan reports
- API endpoints: `DELETE /scans/bulk`, `POST /scans/bulk/archive`, `GET /scans/archives`

#### Error Handling & Observability
- Per-tool error tracking with detailed error breakdown
- New endpoint: `GET /scans/{scan_id}/errors` for error analysis
- Centralized toast notification service in frontend
- Error dialog in ScansView with per-tool status display
- Safe error message extraction to prevent information leakage

#### Operational Features
- Orphan scan recovery on API startup
- Dynamic AWS profile support with `aws_profile` field in scan creation
- Assumed role analysis endpoint (`POST /api/assumed-roles/analyze`) and UI
- Expected exit codes handling: security tools returning 1 or 3 no longer incorrectly marked as failed
- On-demand Docker image building for security tools
- IMDS scan credentials support for EC2/ECS environments

#### Security Analysis Features
- Privilege escalation path analyzer for IAM policy analysis
- Attack path analysis feature for penetration testing
- MCP server for LLM integration and enhanced scan/compliance features

#### UI Enhancements
- Compliance detail view with framework breakdown
- Tool execution monitoring in scan details
- Vue.js frontend with enhanced findings display and PoC evidence

#### Enhanced Scan Orchestration System
- **Docker SDK Integration**: Replaced subprocess-based shell script orchestration with direct Docker SDK calls for reliable container management
- **All AWS Tools Configured**: Added comprehensive tool configurations for all AWS security tools:
  - Prowler (v4.2.4) - AWS compliance and security scanning
  - ScoutSuite (v5.12.0) - Multi-cloud security auditing
  - CloudFox (v1.14.2) - AWS attack surface enumeration
  - CloudSploit - AWS security configuration scanning
  - Cloud Custodian (v0.9.34) - Policy-as-code enforcement
  - CloudMapper - AWS account visualization
  - Cartography (v0.94.0) - Asset relationship graphing to Neo4j
- **Profile-Specific Options**: Scan profiles now support tool-specific command options:
  - Quick: Prowler with critical/high severity filter
  - Comprehensive: All 7 AWS tools with full scanning
  - Compliance-Only: Prowler + ScoutSuite with CIS, SOC2, PCI-DSS frameworks
- **Dynamic Profile Endpoint**: `/api/scans/profiles/list` now returns tool lists dynamically from configuration
- **Entrypoint Override Support**: Tools like CloudSploit that require custom entrypoints are now supported

#### Build & Testing
- Multi-stage Docker build for frontend (no manual build required)
- Integration tests for scan pipeline (`api/tests/test_report_processing.py`)
- Smoke test script (`scripts/smoke_test.sh`)

### Fixed
- Docker network detection now works with any project directory name
- HOST_PROJECT_PATH defaulting to empty string issue
- Docker network name mismatch preventing scan launches
- Report processing for findings population
- Button spacing in Assumed Role Mapper view
- Prowler compliance framework (corrected to `pci_3.2.1_aws`)
- Removed broken ScoutSuite ruleset option
- Exit code handling: security tools returning exit code 3 (Prowler with findings) no longer incorrectly marked as failed
- Container name conflicts: unique execution IDs prevent container naming conflicts during concurrent scans
- Credentials mount to allow saving profiles
- Docker Compose profiles for improved startup reliability
- ESLint configuration for Vue/PrimeVue patterns

### Changed
- Improved error handling with meaningful user-facing messages
- Frontend build moved to Docker container (multi-stage build)
- Report processor dependencies added to API container
- CloudMapper Dockerfile updated to Python 3.9
- Tool images updated: All Docker images now pinned to specific versions matching docker-compose.yml
- Scan orchestration flow: Sequential tool execution with proper completion detection and report processing
- Profiles endpoint: Now returns comprehensive profile metadata including tools list and duration estimates
- Comprehensive documentation added for new features

---

## [1.0.1] - 2026-01-09

### Fixed
- Various bugs discovered during beta testing
- Improved stability across all scanning tools

---

## [1.0.0] - 2026-01-08

### Added

#### Core Platform
- Docker Compose orchestration for 20+ security scanning tools
- Multi-cloud support for AWS, Azure, GCP, and OCI
- Kubernetes security scanning capabilities
- Infrastructure-as-Code security analysis
- PostgreSQL database for centralized findings storage
- Neo4j graph database for asset relationship mapping
- Grafana dashboards for security posture visualization
- REST API (FastAPI) for programmatic access
- Nginx web server for report viewing

#### Cloud Security Tools
- **AWS**: Prowler, ScoutSuite, Pacu, CloudSploit, Cloud Custodian, Cartography
- **Azure**: ScoutSuite, CloudSploit, Cloud Custodian
- **GCP**: Prowler, ScoutSuite, CloudSploit, Cartography
- **OCI**: CloudSploit

#### Kubernetes Security Tools
- kube-bench for CIS Kubernetes Benchmark
- Kubescape for NSA, MITRE ATT&CK, and CIS frameworks
- kube-hunter for penetration testing
- kube-linter for static analysis
- Polaris for best practices validation
- Trivy for container vulnerability scanning
- Grype for container image analysis
- Popeye for resource analysis
- Falco for runtime threat detection

#### IaC Security Tools
- Checkov for Terraform, CloudFormation, Kubernetes, Helm, ARM
- Terrascan for policy-as-code enforcement
- tfsec for Terraform security scanning

#### Scan Management
- Scan profiles: quick, comprehensive, compliance-only
- Severity filtering for targeted scanning
- Dry-run mode for command preview
- JSON output for automation
- Scan comparison with MTTR metrics

#### Update System
- `scripts/update.sh` for comprehensive stack updates
- Tool image version tracking in `data/versions.json`
- Category-based update filtering (aws, kubernetes, iac, infrastructure)
- Rollback capability for tools and stack
- Health validation after updates

#### Permission Validation
- `scripts/check-permissions.py` for pre-flight credential validation
- Support for AWS, Azure, GCP, and Kubernetes
- Remediation instructions for missing permissions
- CLI credential overrides

#### Export and Reporting
- Multiple report formats: HTML, JSON, CSV
- REST API endpoints for data export
- Historical tracking in PostgreSQL
- Asset visualization in Neo4j

### Security
- Credential isolation via Docker volume mounts
- Network segmentation with Docker networks
- API key authentication support
- Gitignore for sensitive directories

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.3 | 2026-01-18 | Phase 1 Open Source features: alert prioritization, threat intel, scheduling, notifications, dashboard |
| 1.0.2 | 2025-01-14 | Security fixes, bulk operations, error handling improvements |
| 1.0.1 | 2026-01-09 | Bug fixes from beta testing |
| 1.0.0 | 2026-01-08 | Initial release |

---

## Upgrade Notes

### Upgrading to 1.0.3
No breaking changes. Apply database migration and rebuild:
```bash
git pull origin main
docker exec -i postgresql psql -U auditor -d security_audits < db-migrations/001_phase1_features.sql
docker compose build api && docker compose up -d api
```

### Upgrading to 1.0.2
No breaking changes. Run:
```bash
git pull origin main
docker compose build api
docker compose up -d
```

### Upgrading to 1.0.1
No breaking changes. Simply run:
```bash
git pull origin main
docker-compose pull
docker-compose up -d
```

---

[Unreleased]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Su1ph3r/Nubicustos/releases/tag/v1.0.0
