# Cloud Security Audit Stack - Complete Repository

## What's Been Built

A comprehensive, production-ready Docker Compose stack for automated cloud security auditing and penetration testing with **NO remediation script generation** - instead, all findings include detailed remediation guidance with specific commands.

## Key Features

### Core Capabilities
- **Multi-Cloud Support**: AWS, Azure, GCP, OCI, Alibaba Cloud
- **Kubernetes Security**: Complete cluster assessment (CIS, NSA, MITRE)
- **IaC Scanning**: Terraform, CloudFormation, Kubernetes YAML, Helm
- **Container Security**: Image vulnerability scanning with Trivy and Grype
- **Asset Mapping**: Neo4j graph database for visualizing relationships
- **Database Storage**: PostgreSQL for findings with remediation guidance
- **Web Interface**: Nginx for easy report access
- **Export Tools**: Client-ready CSV/ZIP packages with remediation commands

### Security Tools Included (15+)
- **AWS**: Prowler, ScoutSuite, Pacu, CloudSploit, Cloud Custodian, CloudMapper
- **Kubernetes**: kube-bench, Kubescape, kube-hunter, Trivy, Popeye, Falco
- **IaC**: Checkov, Terrascan, tfsec
- **Container**: Trivy, Grype
- **Visualization**: Cartography + Neo4j

## 📁 Repository Structure

```
cloud-security-audit-stack/
├── README.md                   # Complete documentation (17KB)
├── INSTALL.md                  # Quick start guide (4.3KB)
├── CHEATSHEET.md              # Command reference (9.6KB)
├── STRUCTURE.md               # Repository layout (9.9KB)
├── LICENSE                    # MIT License
├── .gitignore                 # Security-focused ignore rules
├── .env.example               # Configuration template
├── docker-compose.yml         # Main orchestration (11KB)
├── init.sql                   # Database schema (9.6KB)
├── nginx.conf                 # Web server config
├── cloudmapper/               # CloudMapper Docker build
│   ├── Dockerfile
│   └── entrypoint.sh
├── scripts/                   # Automation scripts
│   ├── run-all-audits.sh     # Master audit runner
│   └── export-findings.sh    # Client report generator
└── static/                    # Web interface
    └── index.html            # Dashboard landing page
```

## Quick Start

```bash
# 1. Setup
git clone <your-repo-url>
cd cloud-security-audit-stack
cp .env.example .env
# Edit .env with your passwords

# 2. Add credentials
mkdir -p credentials/aws
echo "[default]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET" > credentials/aws/credentials

# 3. Launch
docker-compose up -d

# 4. Run audits
./scripts/run-all-audits.sh

# 5. View results
open http://localhost:8080
```

## How It Works

### Audit Workflow
1. **Scan**: Tools run against cloud environments and Kubernetes clusters
2. **Store**: Findings saved to PostgreSQL with remediation guidance
3. **Visualize**: Neo4j creates asset relationship graphs
4. **Export**: Generate client-ready reports with specific fix commands

### Remediation Approach
- **No executable scripts** - findings include remediation guidance only
- Each finding has detailed CLI commands to fix the issue
- Example remediations for AWS, Azure, GCP, and Kubernetes
- Export to CSV for easy spreadsheet analysis
- Perfect for client delivery in penetration testing reports

### Database Schema
- **findings**: All vulnerabilities with remediation text
- **scans**: Audit metadata and statistics  
- **compliance_mappings**: Framework requirements (CIS, PCI-DSS, HIPAA, etc.)
- **assets**: Cloud resource inventory
- **k8s_resources**: Kubernetes cluster objects
- **container_images**: Image vulnerability tracking

## Example Remediation Output

Findings include commands like:

**AWS S3 Encryption:**
```bash
aws s3api put-bucket-encryption \
    --bucket BUCKET_NAME \
    --server-side-encryption-configuration \
    '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
```

**Kubernetes Network Policy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-traffic
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
    - Ingress
    - Egress
```

## Configuration

All settings in `.env`:
- Database passwords (PostgreSQL, Neo4j)
- Port mappings
- Tool enable/disable flags
- Report retention settings
- Resource limits

## Export Capabilities

```bash
./scripts/export-findings.sh
```

Generates:
- `all_findings_TIMESTAMP.csv` - Complete findings list
- `critical_high_findings_TIMESTAMP.csv` - Priority issues
- `aws_findings_TIMESTAMP.csv` - AWS-specific issues
- `compliance_summary_TIMESTAMP.csv` - Framework coverage
- `summary_TIMESTAMP.txt` - Executive summary
- `security_findings_TIMESTAMP.zip` - Complete package

## Security Considerations

### Protected Files (.gitignore)
- credentials/
- kubeconfigs/
- reports/
- logs/
- .env

### Access Control
- Web interface on localhost:8080 (configurable)
- Database passwords required
- Neo4j authentication enabled
- Docker network isolation

## Compliance Frameworks

Findings mapped to:
- CIS Benchmarks
- PCI-DSS
- HIPAA
- GDPR
- SOC2
- NIST
- NSA Kubernetes Hardening Guide
- MITRE ATT&CK

## Use Cases

### Penetration Testing
- Automated infrastructure assessment
- Configuration review
- Vulnerability identification
- Client-ready reports with remediation

### Configuration Reviews
- Multi-cloud security posture
- Kubernetes cluster hardening
- IaC security validation
- Container image vulnerabilities

### Compliance Audits
- Framework-specific assessments
- Historical tracking
- Trend analysis
- Executive reporting

## Database Queries

```sql
-- Critical findings
SELECT resource_id, title, remediation 
FROM findings 
WHERE severity = 'critical' AND status = 'open';

-- Compliance coverage
SELECT * FROM compliance_coverage;

-- Top vulnerable resources
SELECT resource_type, COUNT(*) 
FROM findings 
GROUP BY resource_type 
ORDER BY COUNT(*) DESC;
```

## Documentation

- **README.md**: Complete guide with examples
- **INSTALL.md**: 5-minute quick start
- **CHEATSHEET.md**: Common commands and operations
- **STRUCTURE.md**: Repository organization
- **Web Interface**: Dashboard at http://localhost:8080

## Deployment

### System Requirements
- Docker Engine 20.10+
- Docker Compose 2.0+
- 16GB RAM (32GB recommended)
- 50GB disk space
- Cloud provider credentials

### Production Considerations
- Run on isolated network segment
- Use read-only cloud credentials
- Enable database backups
- Configure log rotation
- Restrict web interface access

## GitHub Repository

This is structured as a complete GitHub repository:

1. **Clone and push to your private GitHub**
2. **All security files properly gitignored**
3. **Comprehensive documentation included**
4. **Ready for immediate use**

## Important Notes

1. **No Script Execution**: This stack identifies issues and provides remediation guidance - it does NOT automatically execute fixes
2. **Credentials Security**: Never commit credentials to Git
3. **Authorization Required**: Only scan infrastructure you're authorized to test
4. **Client Delivery**: Export findings include all necessary remediation commands

## What Makes This Special

- **No LLM Integration**: Pure security tool orchestration
- **No External Dependencies**: Self-contained Docker stack
- **Remediation Guidance**: Not scripts - detailed commands for clients
- **Production Ready**: Comprehensive error handling and logging
- **Well Documented**: 40KB+ of documentation
- **Fully Automated**: One command to run complete audit
- **Export Friendly**: Perfect for penetration testing reports

## Next Steps

1. Push to your private GitHub repository
2. Configure cloud provider credentials
3. Run your first audit: `./scripts/run-all-audits.sh`
4. View results at http://localhost:8080
5. Export findings for client delivery

---

**Ready to deploy!** All files are in the outputs directory and ready to push to GitHub.
