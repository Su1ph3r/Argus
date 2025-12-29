# Repository Structure

This document provides a comprehensive overview of the Cloud Security Audit Stack repository structure.

```
cloud-security-audit-stack/
├── README.md                      # Main documentation
├── INSTALL.md                     # Quick installation guide
├── LICENSE                        # MIT License
├── .gitignore                     # Git ignore rules
├── .env.example                   # Environment variables template
├── docker-compose.yml             # Main orchestration file
├── init.sql                       # PostgreSQL database schema
├── nginx.conf                     # Nginx web server configuration
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
│   ├── export-findings.sh        # Export findings for clients
│   ├── run-audit.sh              # Single provider audit (optional)
│   └── cleanup-old-reports.sh    # Maintenance script (optional)
│
├── cloudmapper/                   # CloudMapper Docker build
│   ├── Dockerfile
│   └── entrypoint.sh
│
└── static/                        # Web interface static files
    ├── index.html                 # Landing page
    ├── css/
    └── js/
```

## Directory Purposes

### Root Configuration Files

- **docker-compose.yml**: Defines all security scanning services, databases, and web interface
- **init.sql**: PostgreSQL database schema for storing findings and compliance data
- **nginx.conf**: Web server configuration for accessing reports
- **.env**: Environment variables (passwords, ports, feature flags)

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
postgres-data       # PostgreSQL database
neo4j-data          # Neo4j graph database
neo4j-logs          # Neo4j logs
neo4j-plugins       # Neo4j extensions
pacu-data           # Pacu AWS testing data
trivy-cache         # Trivy vulnerability database
grype-cache         # Grype vulnerability database
```

## Data Flow

```
1. Cloud APIs
   ↓
2. Security Scanning Tools (Docker containers)
   ↓
3. Reports Directory (JSON/HTML/CSV)
   ↓
4. PostgreSQL Database (structured findings)
   ↓
5. Neo4j Graph (asset relationships)
   ↓
6. Nginx Web Interface
   ↓
7. Export Scripts (client packages)
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
