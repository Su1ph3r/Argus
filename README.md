# Nubicustos

> Cloud Security Guardian - Automated multi-cloud security auditing platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Required-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Version](https://img.shields.io/badge/Version-1.0.2-green.svg)](CHANGELOG.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Cloud Support](https://img.shields.io/badge/Cloud-AWS%20%7C%20Azure%20%7C%20GCP%20%7C%20OCI-orange.svg)](#multi-cloud-support)

*Named from Latin: nubes (cloud) + custos (guardian)*

---

## What is Nubicustos?

Nubicustos is a comprehensive Docker Compose-based platform that orchestrates **20+ security scanning tools** for automated cloud security auditing. It provides unified vulnerability identification, compliance assessment, and remediation guidance across AWS, Azure, GCP, and Kubernetes environments.

### Key Features

- **Multi-Cloud Security Scanning** - Unified scanning across AWS, Azure, GCP, and OCI
- **Kubernetes Security** - CIS benchmarks, runtime detection, and policy validation
- **Infrastructure-as-Code Analysis** - Terraform, CloudFormation, Helm, and ARM template scanning
- **Container Security** - Image vulnerability scanning with Trivy and Grype
- **Attack Path Analysis** - Graph-based attack chain discovery with MITRE ATT&CK mapping
- **AWS Security Deep-Dive** - IMDS checks, Lambda analysis, privilege escalation paths, exposed credentials
- **Web Frontend** - Vue.js 3 dashboard with 22+ specialized views for findings, attack paths, and compliance
- **MCP Server Integration** - LLM integration via Model Context Protocol for AI-assisted security analysis
- **Centralized Findings Database** - PostgreSQL for historical tracking and trend analysis
- **Asset Relationship Mapping** - Neo4j graph database via Cartography
- **REST API** - 20+ endpoint groups for comprehensive programmatic access
- **Remediation Knowledge Base** - AWS CLI commands and step-by-step guidance
- **Scan Profiles** - Quick, comprehensive, and compliance-only presets with Docker SDK orchestration

#### New in v1.0.2

- **Bulk Scan Operations** - Multi-select, bulk delete, and archive functionality from UI and API
- **Per-Tool Error Tracking** - Detailed error breakdown and `/scans/{id}/errors` analysis endpoint
- **Archive Service** - Create and download zip archives of scan reports
- **Orphan Scan Recovery** - Automatic scan recovery on API restart
- **Dynamic AWS Profiles** - Per-scan AWS credential profile selection via `aws_profile` field
- **Enhanced Security** - Path traversal protection, zip slip prevention, log sanitization

---

## Quick Start

Get up and running in under 5 minutes:

```bash
# 1. Clone the repository
git clone https://github.com/Su1ph3r/Nubicustos.git
cd Nubicustos

# 2. Configure environment
cp .env.example .env
# Edit .env with your database passwords

# 3. Launch the core stack
docker compose up -d

# 4. Verify services are running
docker compose ps
# Should show: postgresql, neo4j, nginx, api, report-processor

# 5. Access the web interface
open http://localhost:8080

# 6. Configure credentials via UI
# Navigate to Credentials page and add your cloud credentials
# Or mount credentials manually:
mkdir -p credentials/aws
cp ~/.aws/credentials credentials/aws/
cp ~/.aws/config credentials/aws/

# 7. Run scans via UI or API
# Use the Scans page in the web interface, or:
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "aws_profile": "default"}'
```

> **Note:** Security scanning tools run on-demand via the API/UI rather than as persistent containers.
> This keeps the default deployment lightweight and avoids pulling 20+ tool images at startup.

---

## Architecture

```
                              NUBICUSTOS v1.0.2
    ================================================================

    CLOUD SECURITY TOOLS              KUBERNETES SECURITY
    ==================                ==================
    Prowler         ScoutSuite        kube-bench    Kubescape
    Pacu            CloudSploit       kube-hunter   Trivy
    Cloud Custodian Cartography       Popeye        Grype
    CloudFox        Enumerate-IAM     kube-linter   Polaris
    CloudMapper                       Falco

    IAC SCANNERS                      ORCHESTRATION
    ============                      =============
    Checkov                           Docker SDK Integration
    Terrascan                         On-demand Tool Launching
    tfsec                             Per-Tool Error Tracking
                                      Orphan Scan Recovery

    DATA LAYER                        INTEGRATIONS
    ==========                        ============
    PostgreSQL (Findings DB)          MCP Server (LLM Integration)
    Neo4j (Asset Graph)               Grafana Dashboards (:3000)
    Archive Service (ZIP)             Attack Path Analyzer
    Report Processor                  Assumed Role Analyzer

    ACCESS LAYER
    ============
    REST API (FastAPI :8000)          Bulk Operations API
    Vue.js Frontend (:8080)           Error Analysis Endpoint
    Neo4j Browser (:7474)             Archive Management API
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](INSTALL.md) | Detailed setup instructions |
| [Cheatsheet](CHEATSHEET.md) | Quick reference for common commands |
| [MCP Server Guide](nubicustos-mcp/README.md) | LLM integration via Model Context Protocol |
| [Contributing](CONTRIBUTING.md) | How to contribute to the project |
| [Changelog](CHANGELOG.md) | Version history and release notes |
| [Architecture](STRUCTURE.md) | Detailed architecture documentation |

---

## Multi-Cloud Support

### AWS
- **Prowler** - AWS security best practices and CIS benchmarks
- **ScoutSuite** - Multi-service security auditing
- **Pacu** - AWS exploitation framework for testing
- **CloudFox** - AWS attack surface enumeration
- **Enumerate-IAM** - Comprehensive IAM permission mapping
- **CloudSploit** - Configuration security scanning
- **Cloud Custodian** - Policy-based governance
- **CloudMapper** - AWS account visualization

### Azure
- **ScoutSuite** - Azure security configuration review
- **CloudSploit** - Azure resource scanning
- **Cloud Custodian** - Azure policy enforcement

### GCP
- **Prowler** - GCP security posture assessment
- **ScoutSuite** - GCP multi-service auditing
- **CloudSploit** - GCP configuration scanning

### Kubernetes
- **kube-bench** - CIS Kubernetes Benchmark
- **Kubescape** - NSA, MITRE ATT&CK frameworks
- **kube-hunter** - Penetration testing
- **Trivy** - Container vulnerability scanning
- **Falco** - Runtime threat detection
- **Polaris** - Best practices validation

### Infrastructure-as-Code
- **Checkov** - Terraform, CloudFormation, Kubernetes, Helm
- **Terrascan** - Policy-as-code engine
- **tfsec** - Terraform security scanner

---

## Web Frontend

Nubicustos includes a modern Vue.js 3 web interface with 22+ specialized views:

| View | Description |
|------|-------------|
| **Dashboard** | Security posture overview with critical metrics |
| **Findings** | Searchable list with severity filtering and export |
| **Attack Paths** | Graph visualization of discovered attack chains |
| **Compliance** | Framework compliance status (CIS, SOC2, PCI-DSS) |
| **Compliance Detail** | Framework-specific control breakdown |
| **Scans** | Scan history, orchestration, bulk operations, and monitoring |
| **Public Exposures** | Exposed resources and attack surface |
| **Exposed Credentials** | Leaked credential detection |
| **Privilege Escalation** | IAM lateral movement paths |
| **Privesc Paths** | Detailed privilege escalation path explorer |
| **Assumed Roles** | IAM role assumption analysis |
| **IMDS Checks** | EC2 metadata service vulnerabilities |
| **Lambda Analysis** | Serverless security assessment |
| **CloudFox** | AWS enumeration results |
| **Pacu** | AWS exploitation findings |
| **Enumerate IAM** | IAM permission mapping |
| **Credentials** | Cloud credential profile management |
| **Settings** | Configuration management |

Access the frontend at `http://localhost:8080` after starting the stack.

---

## Attack Path Analysis

Nubicustos automatically discovers attack paths through your cloud infrastructure:

- **Graph-based discovery** - Identifies multi-step attack chains
- **Entry point mapping** - Shows where attackers could gain initial access
- **MITRE ATT&CK integration** - Maps findings to tactics and techniques
- **Exploitability scoring** - Rates paths by likelihood of exploitation (0-100)
- **Impact scoring** - Assesses potential damage if exploited
- **PoC commands** - Generates AWS CLI commands to verify findings

```bash
# Via API
curl http://localhost:8000/api/attack-paths

# View specific path
curl http://localhost:8000/api/attack-paths/path-123
```

---

## MCP Server Integration

Integrate Nubicustos with LLMs via the Model Context Protocol (MCP) server:

```bash
# Install MCP server
cd nubicustos-mcp
pip install -e .
```

### Claude Desktop Configuration

Add to `~/.config/claude/config.json`:

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

### Available MCP Tools

| Category | Tools |
|----------|-------|
| **Scan Management** | list_scans, trigger_scan, get_scan_status, cancel_scan |
| **Finding Queries** | search_findings, get_findings_summary, get_finding_details |
| **Attack Paths** | list_attack_paths, analyze_attack_paths, list_privesc_paths |
| **AWS Security** | get_imds_checks, get_lambda_analysis, run_cloudfox |
| **Exports** | export_findings, get_export_summary |
| **Bulk Operations** | bulk_delete_scans, bulk_archive_scans |
| **Error Analysis** | get_scan_errors, get_tool_status |
| **Archives** | list_archives, download_archive |
| **Assumed Roles** | analyze_assumed_roles, list_role_chains |

See [MCP Server Guide](nubicustos-mcp/README.md) for complete documentation.

---

## Usage Examples

### Running Scans

```bash
# Full audit with all tools
./scripts/run-all-audits.sh

# Quick scan (5-10 minutes)
./scripts/run-all-audits.sh --profile quick

# Comprehensive scan (30-60 minutes)
./scripts/run-all-audits.sh --profile comprehensive

# Compliance-focused scan
./scripts/run-all-audits.sh --profile compliance-only

# Filter by severity
./scripts/run-all-audits.sh --severity critical,high

# Preview without execution
./scripts/run-all-audits.sh --dry-run
```

### API Access

```bash
# Health check
curl http://localhost:8000/api/health

# List findings
curl http://localhost:8000/api/findings

# Filter by severity
curl "http://localhost:8000/api/findings?severity=critical"

# Export to CSV
curl http://localhost:8000/api/exports/csv -o findings.csv
```

### Pre-Flight Permission Validation

```bash
# Check all cloud provider permissions
python scripts/check-permissions.py

# Check specific provider
python scripts/check-permissions.py --provider aws

# Export with remediation instructions
python scripts/check-permissions.py --output report.md --remediation
```

### Compare Scans

```bash
# Compare two scans with MTTR metrics
python3 report-processor/compare_scans.py \
  --baseline-id abc123 \
  --current-id def456 \
  --include-mttr
```

### Bulk Operations (v1.0.2)

```bash
# Delete multiple scans
curl -X DELETE http://localhost:8000/api/scans/bulk \
  -H "Content-Type: application/json" \
  -d '{"scan_ids": ["id1", "id2", "id3"]}'

# Archive scans to downloadable ZIP
curl -X POST http://localhost:8000/api/scans/bulk/archive \
  -H "Content-Type: application/json" \
  -d '{"scan_ids": ["id1", "id2"]}'

# List available archives
curl http://localhost:8000/api/scans/archives

# Get per-tool error breakdown for a scan
curl http://localhost:8000/api/scans/{scan_id}/errors
```

### Dynamic AWS Profiles (v1.0.2)

```bash
# Scan with specific AWS credential profile
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "comprehensive", "aws_profile": "prod-audit"}'

# List available AWS profiles
curl http://localhost:8000/api/credentials/aws/profiles
```

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker Engine | 20.10+ | Latest |
| Docker Compose | 2.0+ | Latest |
| RAM | 16GB | 32GB |
| Disk Space | 50GB | 100GB |

---

## Port Reference

| Port | Service | Description |
|------|---------|-------------|
| 8080 | Nginx | Vue.js web frontend |
| 8000 | FastAPI | REST API (20+ endpoint groups) |
| 3000 | Grafana | Dashboards (optional) |
| 5432 | PostgreSQL | Findings database |
| 7474 | Neo4j HTTP | Graph browser |
| 7687 | Neo4j Bolt | Graph connections |

---

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Setting up a development environment
- Code style guidelines
- Pull request process
- Issue reporting

---

## Security

If you discover a security vulnerability, please do NOT open a public issue. Instead, please email the maintainers directly or use GitHub's private vulnerability reporting feature.

### Security Improvements (v1.0.2)

- **Path Traversal Protection** - All file operations validated with `os.path.realpath()` to prevent directory escape
- **Zip Slip Prevention** - Archive extraction secured against path manipulation attacks
- **ReDoS Mitigation** - Input length limits on regex patterns to prevent denial of service
- **Log Sanitization** - Credentials, tokens, and IP addresses automatically redacted from logs
- **Error Information Control** - Limited validation error details to prevent schema disclosure
- **SQLAlchemy Error Handling** - Specific exception handling to prevent information leakage

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

Nubicustos integrates these excellent open-source security tools:

| Tool | Purpose | License |
|------|---------|---------|
| [Prowler](https://github.com/prowler-cloud/prowler) | Cloud Security Posture Management | Apache-2.0 |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security auditing | GPL-2.0 |
| [Kubescape](https://github.com/kubescape/kubescape) | Kubernetes security platform | Apache-2.0 |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS Kubernetes Benchmark | Apache-2.0 |
| [Trivy](https://github.com/aquasecurity/trivy) | Container vulnerability scanner | Apache-2.0 |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC security scanner | Apache-2.0 |
| [Falco](https://github.com/falcosecurity/falco) | Runtime threat detection | Apache-2.0 |
| [Cartography](https://github.com/lyft/cartography) | Asset inventory mapping | Apache-2.0 |

See [NOTICE](NOTICE) for full attribution details.

---

## Roadmap

- [ ] IBM Cloud support
- [ ] SIEM platform integration
- [ ] Slack/Teams notifications
- [ ] Automated scheduled scanning
- [ ] Multi-tenancy support

---

<p align="center">
  <strong>Built for security professionals, by security professionals.</strong>
</p>
