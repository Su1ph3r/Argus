# Repository Structure

This document provides a comprehensive overview of the Nubicustos repository structure.

```
nubicustos/
├── README.md                      # Main documentation
├── INSTALL.md                     # Quick installation guide
├── CHEATSHEET.md                  # Quick reference for common commands
├── CHANGELOG.md                   # Version history and release notes
├── CONTRIBUTING.md                # Contribution guidelines
├── LICENSE                        # MIT License
├── .gitignore                     # Git ignore rules
├── .env.example                   # Environment variables template
├── docker-compose.yml             # Main orchestration file
├── init.sql                       # PostgreSQL database schema
├── nginx.conf                     # Nginx web server configuration
├── pyproject.toml                 # Python project configuration
│
├── api/                           # FastAPI Backend
│   ├── main.py                   # API server entry point
│   ├── config.py                 # Settings management
│   ├── logging_config.py         # Structured logging
│   ├── models/
│   │   ├── database.py           # SQLAlchemy ORM models
│   │   └── schemas.py            # Pydantic request/response schemas
│   ├── routers/                  # API endpoint groups (18+ routers)
│   │   ├── scans.py              # Scan orchestration
│   │   ├── findings.py           # Finding queries
│   │   ├── attack_paths.py       # Attack path API
│   │   ├── compliance.py         # Compliance tracking
│   │   ├── exports.py            # Report generation
│   │   ├── pacu.py               # Pacu AWS exploitation
│   │   ├── cloudfox.py           # CloudFox enumeration
│   │   ├── enumerate_iam.py      # IAM permission mapping
│   │   ├── imds_checks.py        # EC2 metadata vulnerabilities
│   │   ├── lambda_analysis.py    # Serverless security
│   │   ├── exposed_credentials.py # Credential leak detection
│   │   ├── public_exposures.py   # Attack surface monitoring
│   │   ├── privesc_paths.py      # Privilege escalation paths
│   │   └── assumed_roles.py      # Role assumption analysis
│   ├── services/
│   │   ├── docker_executor.py    # Container orchestration
│   │   └── neo4j_sync.py         # Database sync
│   └── tests/                    # Unit & integration tests
│
├── frontend/                      # Vue.js 3 Web Interface
│   ├── src/
│   │   ├── main.js               # App entry point
│   │   ├── App.vue               # Root component
│   │   ├── views/                # 19 Vue view components
│   │   │   ├── DashboardView.vue
│   │   │   ├── FindingsView.vue
│   │   │   ├── AttackPathsView.vue
│   │   │   ├── ComplianceView.vue
│   │   │   ├── ScansView.vue
│   │   │   ├── PublicExposuresView.vue
│   │   │   ├── CredentialsView.vue
│   │   │   ├── PrivescPathsView.vue
│   │   │   ├── ImdsChecksView.vue
│   │   │   ├── LambdaAnalysisView.vue
│   │   │   ├── CloudfoxView.vue
│   │   │   ├── PacuView.vue
│   │   │   ├── EnumerateIamView.vue
│   │   │   └── SettingsView.vue
│   │   ├── components/
│   │   │   ├── layout/           # Navigation, header, sidebar
│   │   │   ├── dashboard/        # Dashboard widgets
│   │   │   ├── findings/         # Finding display components
│   │   │   ├── attack-paths/     # Attack path visualization
│   │   │   └── remediation/      # Remediation guidance
│   │   ├── router/               # Vue Router configuration
│   │   ├── stores/               # Pinia state management
│   │   └── services/             # API client services
│   └── package.json              # Frontend dependencies
│
├── nubicustos-mcp/                # MCP Server for LLM Integration
│   ├── README.md                 # MCP server documentation
│   └── src/nubicustos_mcp/
│       ├── server.py             # FastMCP server instance
│       ├── config.py             # Settings
│       ├── client.py             # Async HTTP client
│       ├── tools/                # MCP tool implementations
│       │   ├── scans.py          # Scan management tools
│       │   ├── findings.py       # Finding query tools
│       │   ├── attack_paths.py   # Attack path tools
│       │   ├── security.py       # Security analysis tools
│       │   ├── cloud.py          # Cloud-specific tools
│       │   ├── exports.py        # Export tools
│       │   └── system.py         # System tools
│       ├── resources/            # MCP resource definitions
│       └── prompts/              # LLM prompt templates
│
├── report-processor/              # Post-Scan Analysis Engine
│   ├── process_reports.py        # Main report processor
│   ├── db_loader.py              # Database insertion
│   ├── attack_path_analyzer.py   # Attack path discovery
│   ├── attack_path_edges.py      # Graph edge definitions
│   ├── remediation_kb.py         # Remediation knowledge base
│   ├── severity_scoring.py       # Risk scoring
│   ├── compare_scans.py          # Scan comparison with MTTR
│   ├── generate_summary.py       # Report summaries
│   └── send_notifications.py     # Alerting
│
├── credentials/                   # Cloud provider credentials (gitignored)
│   ├── aws/
│   │   ├── credentials           # AWS access keys
│   │   └── config                # AWS configuration
│   ├── azure/
│   │   └── credentials.json      # Azure service principal
│   └── gcp/
│       └── credentials.json      # GCP service account key
│
├── kubeconfigs/                   # Kubernetes configs (gitignored)
│   └── config                     # kubectl configuration
│
├── config/                        # Tool-specific configurations
│   ├── cloudsploit/
│   │   └── config.js             # CloudSploit settings
│   └── falco/
│       └── falco.yaml            # Falco rules configuration
│
├── policies/                      # Cloud Custodian policies
│   ├── aws/
│   │   ├── s3-encryption.yml
│   │   ├── security-groups.yml
│   │   └── iam-policies.yml
│   ├── azure/
│   │   └── storage-security.yml
│   └── gcp/
│       └── bucket-security.yml
│
├── iac-code/                      # Infrastructure-as-Code to scan (gitignored)
│   ├── terraform/
│   ├── cloudformation/
│   ├── kubernetes/
│   └── helm/
│
├── reports/                       # All scan outputs (gitignored)
│   ├── prowler/
│   │   ├── prowler-output-*.html
│   │   ├── prowler-output-*.json
│   │   └── prowler-output-*.csv
│   ├── scoutsuite/
│   │   └── scoutsuite-report/
│   │       └── index.html
│   ├── pacu/
│   ├── cloudfox/
│   ├── cloudsploit/
│   │   └── output.json
│   ├── custodian/
│   ├── cloudmapper/
│   ├── kube-bench/
│   │   └── kube-bench-report.json
│   ├── kubescape/
│   │   └── kubescape-results.json
│   ├── kube-hunter/
│   │   └── kube-hunter.json
│   ├── trivy/
│   ├── grype/
│   ├── popeye/
│   │   └── popeye-report.json
│   ├── checkov/
│   ├── terrascan/
│   │   └── terrascan-results.json
│   ├── tfsec/
│   │   └── tfsec-results.json
│   └── exports/                   # Client-ready export packages
│       ├── all_findings_*.csv
│       ├── critical_high_findings_*.csv
│       ├── aws_findings_*.csv
│       ├── compliance_summary_*.csv
│       ├── summary_*.txt
│       ├── README_*.txt
│       └── security_findings_*.zip
│
├── logs/                          # Application logs (gitignored)
│   ├── audit-*.log
│   ├── prowler.log
│   ├── custodian.log
│   ├── postgresql/
│   ├── nginx/
│   └── falco/
│
├── scripts/                       # Automation scripts
│   ├── run-all-audits.sh         # Master audit execution script
│   ├── check-permissions.py      # Pre-flight credential validation
│   ├── export-findings.sh        # Export findings for clients
│   ├── neo4j-sync.sh             # Database sync
│   ├── update.sh                 # Version management
│   └── cleanup-old-reports.sh    # Maintenance script (optional)
│
├── tools/                         # Custom tool builds
│   └── enumerate-iam/
│       └── Dockerfile
│
├── data/                          # Metadata and reference data
│   └── versions.json             # Tool version tracking
│
├── cloudmapper/                   # CloudMapper Docker build
│   ├── Dockerfile
│   └── entrypoint.sh
│
└── .github/                       # GitHub configuration
    ├── workflows/                # CI/CD workflows
    ├── ISSUE_TEMPLATE/
    ├── PULL_REQUEST_TEMPLATE.md
    └── SECURITY.md
```

## Directory Purposes

### Root Configuration Files

- **docker-compose.yml**: Defines all security scanning services, databases, and web interface
- **init.sql**: PostgreSQL database schema for storing findings and compliance data
- **nginx.conf**: Web server configuration for serving Vue.js frontend
- **pyproject.toml**: Python project configuration with dependencies and tool settings
- **.env**: Environment variables (passwords, ports, feature flags)

### API Directory

**Purpose**: FastAPI backend providing REST API access to all platform features

**Key Components**:
- **main.py**: API server entry point with middleware configuration
- **routers/**: 18+ endpoint groups for scans, findings, attack paths, compliance, etc.
- **models/**: SQLAlchemy ORM models and Pydantic schemas
- **services/**: Docker SDK executor and Neo4j sync services

**API Endpoint Groups**:
- `/scans`: Scan orchestration and profiles
- `/findings`: Vulnerability queries and filtering
- `/attack-paths`: Attack chain analysis
- `/compliance`: Framework compliance tracking
- `/exports`: Report generation (CSV, JSON)
- `/pacu`, `/cloudfox`, `/enumerate-iam`: AWS security tools
- `/imds-checks`, `/lambda-analysis`: AWS-specific security
- `/privesc-paths`, `/public-exposures`, `/exposed-credentials`: Threat hunting

### Frontend Directory

**Purpose**: Vue.js 3 web interface with 19 specialized security views

**Stack**:
- Vue 3 with Composition API
- Vue Router for navigation
- Pinia for state management
- PrimeVue UI components
- Chart.js for visualizations

**Key Views**:
- Dashboard, Findings, Attack Paths, Compliance
- Scans, Public Exposures, Credentials
- IMDS Checks, Lambda Analysis, CloudFox, Pacu
- Privilege Escalation, Enumerate IAM, Settings

### Nubicustos-MCP Directory

**Purpose**: Model Context Protocol server for LLM integration

**Capabilities**:
- 27+ tools for querying and triggering security operations
- 6 resource URIs for accessing security data
- 8+ prompt templates for analysis workflows
- Compatible with Claude Desktop, Ollama, LM Studio

**Tool Categories**:
- Scan management (list, trigger, status, cancel)
- Finding queries (search, summary, details)
- Attack path analysis
- Cloud-specific tools (IMDS, Lambda, IAM)
- Export and system operations

### Report-Processor Directory

**Purpose**: Post-scan analysis engine for findings processing

**Key Modules**:
- **attack_path_analyzer.py**: Graph-based attack chain discovery
- **remediation_kb.py**: AWS CLI remediation commands
- **severity_scoring.py**: Risk scoring with CVSS-inspired metrics
- **compare_scans.py**: Scan comparison with MTTR tracking
- **db_loader.py**: Findings insertion to PostgreSQL

### Credentials Directory

**Purpose**: Store cloud provider and Kubernetes authentication credentials

**Security**: 
- Excluded from git via .gitignore
- Should have restrictive permissions (chmod 600)
- Never commit to version control

**Contents**:
- AWS: IAM credentials with read-only security audit permissions
- Azure: Service principal with Security Reader role
- GCP: Service account with Security Reviewer role
- Kubernetes: kubeconfig with cluster access

### Config Directory

**Purpose**: Tool-specific configuration files

**Use Cases**:
- CloudSploit: API keys and scanning rules
- Falco: Runtime detection rules
- Custom scanning parameters

### Policies Directory

**Purpose**: Cloud Custodian policy-as-code definitions

**Structure**: Organized by cloud provider
- AWS: S3, EC2, IAM, VPC policies
- Azure: Storage, Network, KeyVault policies  
- GCP: Storage, Compute, IAM policies

**Format**: YAML files defining security policies

### IaC-Code Directory

**Purpose**: Infrastructure-as-Code files to be scanned for security issues

**Supported**:
- Terraform (.tf files)
- CloudFormation (.yaml, .json templates)
- Kubernetes manifests (.yaml)
- Helm charts
- ARM templates

**Workflow**:
1. Copy/mount your IaC code here
2. Run scans with Checkov, Terrascan, tfsec
3. Review findings in reports

### Reports Directory

**Purpose**: All security scan outputs

**Organization**: One subdirectory per tool

**Formats**:
- JSON: Machine-readable findings
- HTML: Human-readable reports
- CSV: Spreadsheet-compatible exports

**Key Subdirectories**:
- **exports/**: Client-ready packages with all findings and remediation guidance
  - CSV files for spreadsheet analysis
  - Summary statistics
  - README with remediation instructions
  - ZIP archives for easy distribution

### Logs Directory

**Purpose**: Audit trails and application logs

**Contents**:
- Master audit execution logs
- Individual tool logs
- Database query logs
- Web server access logs
- Runtime detection events (Falco)

**Retention**: Logs are retained based on REPORT_RETENTION_DAYS setting

### Scripts Directory

**Purpose**: Automation and workflow scripts

**Scripts**:
- **run-all-audits.sh**: Orchestrates complete security audit across all platforms
- **export-findings.sh**: Generates client-ready reports with remediation guidance
- Additional helper scripts for specific tasks

**Usage**: All scripts are executable and can be run directly

### CloudMapper Directory

**Purpose**: Docker build context for CloudMapper AWS visualization

**Contents**:
- Dockerfile for CloudMapper image
- Entrypoint script for automated scanning

## File Naming Conventions

### Reports
```
{tool}-output-{timestamp}.{format}
prowler-output-20240115_143022.json
kubescape-results-20240115_143500.json
```

### Exports
```
{type}_findings_{timestamp}.csv
all_findings_20240115_150000.csv
critical_high_findings_20240115_150000.csv
aws_findings_20240115_150000.csv
```

### Logs
```
audit-{timestamp}.log
{tool}.log
```

## Docker Volumes

Persistent data stored in named Docker volumes:

```
postgres-data       # PostgreSQL findings database
neo4j-data          # Neo4j asset graph database
neo4j-logs          # Neo4j logs
neo4j-plugins       # Neo4j extensions
pacu-data           # Pacu AWS testing data
cloudfox-data       # CloudFox enumeration data
trivy-cache         # Trivy vulnerability database
grype-cache         # Grype vulnerability database
```

## Data Flow

```
1. Cloud APIs / Kubernetes Clusters
   ↓
2. Security Scanning Tools (Docker containers via Docker SDK)
   ↓
3. Reports Directory (JSON/HTML/CSV)
   ↓
4. Report Processor (attack paths, severity scoring, remediation)
   ↓
5. PostgreSQL Database (structured findings, attack paths)
   ↓
6. Neo4j Graph (asset relationships via Cartography)
   ↓
7. FastAPI REST API (programmatic access)
   ↓
8. Vue.js Frontend / MCP Server (user interfaces)
   ↓
9. Export Scripts (client packages, CSV, JSON)
```

## Adding New Tools

To add a new security tool:

1. Add service to `docker-compose.yml`
2. Mount credentials and reports volumes
3. Configure output directory
4. Update `scripts/run-all-audits.sh`
5. Add export logic to `scripts/export-findings.sh`

## Backup Strategy

**What to Backup**:
- PostgreSQL database (findings and history)
- Neo4j graph data (asset relationships)
- Reports directory (scan outputs)
- Credentials (encrypted, separate storage)

**What NOT to Backup**:
- Docker images (can be rebuilt)
- Cache volumes (trivy-cache, grype-cache)
- Logs (unless required for compliance)

**Backup Commands**:
```bash
# Database
docker-compose exec postgresql pg_dump -U auditor security_audits > backup.sql

# Neo4j
docker-compose exec neo4j neo4j-admin dump --to=/data/neo4j-backup.dump

# Reports
tar -czf reports-backup.tar.gz reports/
```

## Maintenance

**Regular Tasks**:
- Clean old reports: `find reports/ -mtime +90 -delete`
- Vacuum database: `docker-compose exec postgresql vacuumdb -U auditor -d security_audits`
- Update tool images: `docker-compose pull`
- Rotate logs: Configure in docker-compose.yml

**Disk Space Management**:
- Reports: ~1GB per full audit
- Database: ~500MB per 10,000 findings
- Docker images: ~10GB total
- Recommend: 50GB+ free space

## Security Considerations

**Sensitive Files** (git ignored):
- credentials/
- kubeconfigs/
- reports/
- logs/
- .env

**Access Control**:
- Restrict web interface (Nginx) to internal network
- Use strong database passwords
- Rotate credentials regularly
- Enable authentication on Neo4j

**Network Isolation**:
- All containers on isolated bridge network
- Only Nginx exposed externally
- Database ports not exposed to host (optional)
