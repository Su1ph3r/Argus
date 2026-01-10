# Nubicustos

A comprehensive Docker Compose stack for automated cloud security auditing, vulnerability identification, and remediation script generation across multiple cloud providers and Kubernetes environments.

*Named from Latin: nubes (cloud) + custos (guardian) - the Cloud Guardian.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![Cloud](https://img.shields.io/badge/cloud-AWS%20%7C%20Azure%20%7C%20GCP%20%7C%20OCI-orange.svg)

## Purpose

This stack is designed for **penetration testing** and **security configuration reviews**, focusing on:
- Automated vulnerability identification across cloud environments
- Kubernetes cluster security assessment
- Infrastructure-as-Code (IaC) security scanning
- Container image vulnerability analysis
- Automatic generation of remediation scripts
- Historical tracking of security posture

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Nubicustos                            │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   AWS Tools  │  │ Azure Tools  │  │  GCP Tools   │      │
│  │              │  │              │  │              │      │
│  │  • Prowler   │  │ • ScoutSuite │  │ • CloudSploit│      │
│  │  • Pacu      │  │ • Cloud      │  │ • Prowler    │      │
│  │  • ScoutSuite│  │   Custodian  │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Kubernetes Security Tools                   │   │
│  │                                                        │   │
│  │  • kube-bench    • kubescape    • kube-hunter        │   │
│  │  • Trivy         • Popeye       • Falco              │   │
│  │  • kube-linter   • Polaris                           │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │        Infrastructure-as-Code Security                │   │
│  │                                                        │   │
│  │  • Checkov       • Terrascan    • tfsec              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  PostgreSQL  │  │    Neo4j     │  │    Nginx     │      │
│  │   (Storage)  │  │ (Asset Graph)│  │  (Reports)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────┐                                            │
│  │  FastAPI     │                                            │
│  │  (REST API)  │                                            │
│  └──────────────┘                                            │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Features

### Multi-Cloud Support
- **AWS**: Prowler, ScoutSuite, Pacu, CloudSploit, Cloud Custodian
- **Azure**: ScoutSuite, CloudSploit, Cloud Custodian
- **GCP**: Prowler, ScoutSuite, CloudSploit
- **OCI**: CloudSploit
- **Alibaba Cloud**: CloudSploit

### Kubernetes Security
- **CIS Benchmarks**: kube-bench
- **Compliance Frameworks**: kubescape (NSA, MITRE ATT&CK, CIS)
- **Penetration Testing**: kube-hunter
- **Static Analysis**: kube-linter
- **Best Practices Validation**: Polaris
- **Image Scanning**: Trivy, Grype
- **Runtime Detection**: Falco
- **Resource Analysis**: Popeye

### Infrastructure-as-Code
- **Terraform**: Checkov, Terrascan, tfsec
- **CloudFormation**: Checkov, Terrascan
- **Kubernetes YAML**: Checkov, Kubescape
- **Helm Charts**: Checkov
- **ARM Templates**: Checkov

### Reporting & Analytics
- **Multiple Formats**: HTML, JSON, CSV
- **Historical Tracking**: PostgreSQL database
- **Asset Mapping**: Cartography + Neo4j
- **Web Interface**: Nginx for report viewing
- **Remediation Guidelines**: Detailed commands and steps for fixing issues
- **REST API**: FastAPI for programmatic access

### CLI Features
- **Scan Profiles**: Quick, comprehensive, and compliance-only presets
- **Dry-run Mode**: Preview commands without execution
- **Severity Filtering**: Target specific severity levels
- **JSON Output**: Machine-readable scan summaries
- **Scan Comparison**: Compare findings between scans with MTTR tracking

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 16GB RAM minimum (32GB recommended)
- 50GB free disk space
- Cloud provider credentials (AWS, Azure, GCP)
- Kubernetes cluster access (optional)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Su1ph3r/Nubicustos.git
cd Nubicustos
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit with your settings
nano .env
```

### 3. Setup Cloud Credentials

#### AWS
```bash
mkdir -p credentials/aws
cat > credentials/aws/credentials << EOF
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
EOF

cat > credentials/aws/config << EOF
[default]
region = us-east-1
output = json
EOF
```

#### Azure
```bash
mkdir -p credentials/azure
# Azure CLI login or service principal
az login
# OR
cat > credentials/azure/credentials.json << EOF
{
  "clientId": "YOUR_CLIENT_ID",
  "clientSecret": "YOUR_CLIENT_SECRET",
  "tenantId": "YOUR_TENANT_ID",
  "subscriptionId": "YOUR_SUBSCRIPTION_ID"
}
EOF
```

#### GCP
```bash
mkdir -p credentials/gcp
# Copy your service account JSON
cp ~/path/to/service-account.json credentials/gcp/credentials.json
```

#### Kubernetes
```bash
mkdir -p kubeconfigs
cp ~/.kube/config kubeconfigs/config
```

### 4. Launch the Stack

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 5. Validate Permissions (Pre-Flight Check)

Before running security audits, validate that your credentials have the required permissions:

```bash
# Install Python dependencies (one-time)
pip install boto3 azure-identity azure-mgmt-authorization google-cloud-resource-manager kubernetes

# Check all providers
python scripts/check-permissions.py

# Check specific provider
python scripts/check-permissions.py --provider aws
python scripts/check-permissions.py --provider azure
python scripts/check-permissions.py --provider gcp
python scripts/check-permissions.py --provider kubernetes

# Export results with remediation instructions
python scripts/check-permissions.py --output report.md --remediation
```

The tool will show which permissions are missing and provide step-by-step instructions to fix them.

## Usage

### Running Full Security Audit

```bash
# Run all audits across all platforms
./scripts/run-all-audits.sh

# Using scan profiles
./scripts/run-all-audits.sh --profile quick           # Fast scan (5-10 min)
./scripts/run-all-audits.sh --profile comprehensive   # Full scan (30-60 min)
./scripts/run-all-audits.sh --profile compliance-only # Compliance focused

# CLI options
./scripts/run-all-audits.sh --dry-run                 # Preview without executing
./scripts/run-all-audits.sh --severity critical,high  # Filter by severity
./scripts/run-all-audits.sh --output json             # JSON summary output

# Combine options
./scripts/run-all-audits.sh --profile quick --dry-run --severity critical

# Run specific provider audit
./scripts/run-audit.sh aws
./scripts/run-audit.sh azure
./scripts/run-audit.sh gcp
./scripts/run-audit.sh kubernetes

# Run specific tool
docker-compose run prowler aws --output-modes json,html
docker-compose run kubescape scan --submit=false
```

### Viewing Reports

```bash
# Web interface
open http://localhost:8080/reports

# Neo4j graph database
open http://localhost:7474
# Login: neo4j / cloudsecurity

# Direct file access
ls -R reports/

# Query findings database
docker-compose exec postgresql psql -U auditor -d security_audits
```

### REST API

The stack includes a FastAPI-based REST API for programmatic access:

```bash
# Health check
curl http://localhost:8000/api/health

# List all findings
curl http://localhost:8000/api/findings

# Filter findings by severity
curl "http://localhost:8000/api/findings?severity=critical"

# Filter by cloud provider
curl "http://localhost:8000/api/findings?cloud_provider=aws"

# Get specific finding
curl http://localhost:8000/api/findings/{id}

# Update finding status
curl -X PATCH http://localhost:8000/api/findings/{id} \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved"}'

# Trigger a new scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "providers": ["aws"]}'

# Get scan status
curl http://localhost:8000/api/scans/{scan_id}

# Export findings to CSV
curl http://localhost:8000/api/exports/csv -o findings.csv

# Export findings to JSON
curl http://localhost:8000/api/exports/json -o findings.json
```

### Scan Profiles

Pre-configured profiles optimize scanning for different use cases:

**Quick Profile** (`--profile quick`):
- Prowler (critical/high only)
- Kubescape (NSA framework)
- Checkov
- Estimated time: 5-10 minutes

**Comprehensive Profile** (`--profile comprehensive`):
- All tools enabled
- All severity levels
- Full compliance frameworks
- Estimated time: 30-60 minutes

**Compliance-Only Profile** (`--profile compliance-only`):
- Prowler, kube-bench, Kubescape
- CIS, SOC2, HIPAA frameworks
- Estimated time: 15-20 minutes

**Custom Profiles:**
```yaml
# profiles/custom.yml
name: custom
description: My custom scan profile
tools:
  prowler:
    enabled: true
    severity: critical,high
  kubescape:
    enabled: true
    framework: nsa,cis
  checkov:
    enabled: true
```

### Comparing Scans

Compare findings between scans to track security posture changes:

```bash
# Compare by scan IDs
python3 report-processor/compare_scans.py \
  --baseline-id abc123 \
  --current-id def456

# Compare by dates
python3 report-processor/compare_scans.py \
  --baseline-date 2024-01-01 \
  --current-date 2024-01-15

# Include MTTR (Mean Time To Resolution) metrics
python3 report-processor/compare_scans.py \
  --baseline-id abc123 \
  --current-id def456 \
  --include-mttr

# Output formats
python3 report-processor/compare_scans.py \
  --baseline-id abc123 \
  --current-id def456 \
  --output json    # or: table, csv

# Compare JSON files (backward compatible)
python3 report-processor/compare_scans.py \
  --baseline reports/scan1.json \
  --current reports/scan2.json
```

**Comparison Output Includes:**
- New findings (appeared in current scan)
- Resolved findings (fixed since baseline)
- Persistent findings (unchanged)
- Severity breakdown for each category
- MTTR statistics by severity level

### Container Security Scanning

```bash
# Scan Docker image
docker-compose run trivy image nginx:latest

# Scan Kubernetes manifests
docker-compose run trivy config /iac-code/k8s/

# Scan with Grype
docker-compose run grype nginx:latest
```

### IaC Security Scanning

```bash
# Copy your IaC code
cp -r ~/my-terraform-code iac-code/

# Scan with Checkov
docker-compose run checkov -d /code

# Scan with Terrascan
docker-compose run terrascan scan -i terraform -d /iac

# Scan with tfsec
docker-compose run tfsec /src
```

## Report Formats

Each tool generates reports in multiple formats:

### Prowler
```
reports/prowler/
├── prowler-output-TIMESTAMP.html     # HTML report
├── prowler-output-TIMESTAMP.json     # JSON data
└── prowler-output-TIMESTAMP.csv      # CSV export
```

### ScoutSuite
```
reports/scoutsuite/
└── scoutsuite-report/
    ├── index.html                    # Main dashboard
    └── inc-awsconfig/                # Config data
```

### Kubescape
```
reports/kubescape/
├── results.json                      # Findings
├── summary.html                      # HTML report
└── controls/                         # Control details
```

## Remediation Guidelines

Each finding in the database includes detailed remediation guidance with specific commands to fix the issue:

### Database Query for Remediation

```sql
-- Get all critical findings with remediation steps
SELECT 
    finding_id,
    resource_id,
    title,
    description,
    remediation,
    severity
FROM findings
WHERE severity = 'critical'
AND status = 'open'
ORDER BY scan_date DESC;
```

### Example Remediation Formats

**AWS S3 Bucket Encryption:**
```bash
# Enable default encryption on S3 bucket
aws s3api put-bucket-encryption \
    --bucket BUCKET_NAME \
    --server-side-encryption-configuration \
    '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
```

**Kubernetes Network Policy:**
```yaml
# Apply network policy to restrict pod traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-traffic
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector: {}
```

**Azure Storage Account:**
```bash
# Enable secure transfer required
az storage account update \
    --name STORAGE_ACCOUNT_NAME \
    --resource-group RESOURCE_GROUP \
    --https-only true
```

### Exporting Remediation Reports

Export findings with remediation steps for client delivery:

```bash
# Export to CSV
docker-compose exec postgresql psql -U auditor -d security_audits -c "\COPY (SELECT finding_id, cloud_provider, resource_id, severity, title, remediation FROM findings WHERE status='open') TO '/tmp/remediation_guide.csv' CSV HEADER"

# Copy to reports directory
docker cp postgresql:/tmp/remediation_guide.csv ./reports/
```

## Advanced Features

### Cloud Asset Mapping with Cartography

```bash
# View asset graph
open http://localhost:7474

# Query examples in Neo4j browser:

# Find all public S3 buckets
MATCH (s:S3Bucket {public: true}) RETURN s

# Find EC2 instances with security group issues
MATCH (i:EC2Instance)-[:MEMBER_OF_SECURITY_GROUP]->(sg:SecurityGroup)
WHERE sg.inbound_rules CONTAINS '0.0.0.0/0'
RETURN i, sg

# Find K8s pods without security context
MATCH (p:Pod) WHERE p.securityContext IS NULL RETURN p
```

### Database Queries

```bash
# Connect to PostgreSQL
docker-compose exec postgresql psql -U auditor -d security_audits

# Query findings
SELECT tool, severity, COUNT(*) 
FROM findings 
WHERE scan_date > NOW() - INTERVAL '7 days'
GROUP BY tool, severity;

# Track remediation history
SELECT * FROM remediation_history 
WHERE status = 'completed'
ORDER BY executed_at DESC;
```

### Custom Cloud Custodian Policies

```yaml
# policies/aws/s3-encryption.yml
policies:
  - name: s3-enforce-encryption
    resource: s3
    filters:
      - or:
          - type: value
            key: Encryption
            value: absent
          - type: bucket-encryption
            state: false
    actions:
      - type: set-bucket-encryption
        enabled: true
```

Run custom policies:
```bash
docker-compose run cloud-custodian run \
  -s /reports/custodian /policies/aws/s3-encryption.yml
```

## Database Schema

```sql
-- Findings table
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64),
    tool VARCHAR(64),
    cloud_provider VARCHAR(32),
    resource_type VARCHAR(64),
    resource_id VARCHAR(256),
    finding_id VARCHAR(256),
    severity VARCHAR(16),
    title TEXT,
    description TEXT,
    remediation TEXT,
    compliance_frameworks JSONB,
    metadata JSONB,
    scan_date TIMESTAMP DEFAULT NOW()
);

-- Remediation history
CREATE TABLE remediation_history (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id),
    script_path VARCHAR(512),
    status VARCHAR(32),
    executed_at TIMESTAMP,
    executed_by VARCHAR(128),
    output TEXT,
    rollback_script VARCHAR(512)
);

-- Scan metadata
CREATE TABLE scans (
    scan_id VARCHAR(64) PRIMARY KEY,
    scan_type VARCHAR(64),
    target VARCHAR(256),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(32),
    total_findings INTEGER
);
```

## Security Considerations

### Credential Storage
- **Never commit credentials to Git**
- Use `.gitignore` to exclude `credentials/` directory
- Consider using HashiCorp Vault or AWS Secrets Manager
- Rotate credentials regularly

### Network Security
- Run on isolated network segment
- Use Docker network isolation
- Restrict port exposure (bind to localhost only)
- Enable firewall rules

### Access Control
- Limit database access
- Use strong passwords (see `.env.example`)
- Enable authentication on Neo4j
- Restrict Nginx access

### Audit Logging
- All tool executions logged to `logs/`
- Remediation actions logged to database
- Review logs regularly

## Performance Tuning

### Resource Allocation

```yaml
# docker-compose.yml adjustments for large environments
services:
  prowler:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
```

### Parallel Scanning

```bash
# Run multiple tools simultaneously
docker-compose run -d prowler aws &
docker-compose run -d scoutsuite run aws &
docker-compose run -d cloudsploit &
wait
```

### Report Retention

```bash
# Keep last 30 days of reports
find reports/ -type f -mtime +30 -delete

# Archive old reports
tar -czf reports-archive-$(date +%Y%m%d).tar.gz reports/
```

## Troubleshooting

### Common Issues

**Issue**: Container fails to start
```bash
# Check logs
docker-compose logs [service-name]

# Recreate container
docker-compose up -d --force-recreate [service-name]
```

**Issue**: Credential errors
```bash
# Verify credential files exist
ls -la credentials/

# Test AWS credentials
docker-compose run prowler aws sts get-caller-identity
```

**Issue**: Out of disk space
```bash
# Clean old images
docker system prune -a

# Clean old reports
./scripts/cleanup-old-reports.sh
```

**Issue**: PostgreSQL connection failed
```bash
# Reset database
docker-compose down -v
docker-compose up -d postgresql
```

### Debug Mode

```bash
# Enable verbose logging
export DEBUG=1

# Run with debug output
docker-compose --verbose up

# Check container health
docker-compose exec [service] /bin/bash
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This stack leverages the following open-source security tools:

- [Prowler](https://github.com/prowler-cloud/prowler) - Cloud Security Posture Management
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Cloud security scanning
- [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) - Cloud governance
- [kube-bench](https://github.com/aquasecurity/kube-bench) - Kubernetes CIS benchmarks
- [Kubescape](https://github.com/kubescape/kubescape) - Kubernetes security platform
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Kubernetes penetration testing
- [kube-linter](https://github.com/stackrox/kube-linter) - Static analysis for Kubernetes
- [Polaris](https://github.com/FairwindsOps/polaris) - Kubernetes best practices validation
- [Trivy](https://github.com/aquasecurity/trivy) - Container security scanner
- [Falco](https://github.com/falcosecurity/falco) - Runtime threat detection
- [Checkov](https://github.com/bridgecrewio/checkov) - IaC security scanner
- [Terrascan](https://github.com/tenable/terrascan) - IaC policy engine
- [Cartography](https://github.com/lyft/cartography) - Asset inventory

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review existing documentation in `/docs`
- Check troubleshooting guide above

## Roadmap

- [ ] Add support for IBM Cloud
- [x] Integrate additional K8s tools (kube-linter, polaris)
- [x] API endpoint for programmatic access
- [ ] Automated scheduled scanning
- [ ] Export findings to SIEM platforms
- [ ] Slack/Teams notifications for critical findings
- [ ] Multi-tenancy support

