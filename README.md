# Nubicustos

> **Cloud Security Intelligence Platform** - Transform raw security scans into actionable intelligence with attack path analysis, compliance mapping, and proof-of-concept verification across AWS, Azure, GCP, and Kubernetes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Required-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Version](https://img.shields.io/badge/Version-1.0.3-green.svg)](CHANGELOG.md)
[![GitHub stars](https://img.shields.io/github/stars/Su1ph3r/Nubicustos?style=social)](https://github.com/Su1ph3r/Nubicustos/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/Su1ph3r/Nubicustos)](https://github.com/Su1ph3r/Nubicustos/commits/main)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Cloud Support](https://img.shields.io/badge/Cloud-AWS%20%7C%20Azure%20%7C%20GCP%20%7C%20K8s-orange.svg)](#multi-cloud-support)

*Named from Latin: nubes (cloud) + custos (guardian)*

---

## Why Nubicustos?

Running security scanners is easy. **Understanding what the results mean is hard.**

Nubicustos doesn't just run tools - it transforms raw scanner output into **actionable security intelligence**:

| Challenge | How Nubicustos Solves It |
|-----------|--------------------------|
| **24+ tools, 24+ report formats** | Unified findings database with normalized severity, status, and resource mapping |
| **Thousands of findings, no context** | Attack path analysis correlates findings into exploitable chains |
| **"Is this actually exploitable?"** | Proof-of-concept commands to verify findings in your environment |
| **"Are we compliant?"** | Automatic mapping to 29+ compliance frameworks (CIS, SOC2, PCI-DSS, HIPAA, NIST, etc.) |
| **"What changed since last scan?"** | Historical tracking with MTTR metrics and trend analysis |
| **"How do I fix this?"** | Remediation knowledge base with AWS CLI commands and step-by-step guidance |

---

## Key Capabilities

### Unified Security Intelligence

Nubicustos normalizes output from 24+ security tools into a single, queryable database:

- **One view for all findings** - No more switching between tool-specific dashboards
- **Consistent severity mapping** - Critical/High/Medium/Low regardless of source tool
- **Resource correlation** - See all findings for a specific resource across all tools
- **Deduplication** - Identify when multiple tools flag the same issue

### Attack Path Discovery

Go beyond individual findings to understand **how attackers could chain vulnerabilities**:

- **Graph-based analysis** - Identifies multi-step attack chains through your infrastructure
- **Entry point mapping** - Shows where attackers could gain initial access
- **MITRE ATT&CK integration** - Maps attack paths to tactics and techniques
- **Risk scoring (0-100)** - Prioritize paths by exploitability and impact
- **PoC generation** - AWS CLI commands to verify each step is exploitable

### Compliance Mapping

Automatically map findings to **29+ compliance frameworks**:

- AWS CIS Benchmarks (1.4, 1.5, 2.0, 2.1, 3.0)
- SOC 2, PCI-DSS 3.2.1, HIPAA
- NIST 800-53 (Rev 4 & 5), NIST 800-171, NIST CSF
- FedRAMP (Low & Moderate), CISA
- GDPR, ISO 27001, MITRE ATT&CK
- AWS Well-Architected Framework (Security & Reliability Pillars)
- And more...

### Proof of Concept Verification

Don't just report findings - **prove they're exploitable**:

- **PoC commands** - Generated AWS CLI commands to verify findings
- **Secret verification** - TruffleHog validates credentials are actually active
- **Privilege escalation paths** - PMapper shows exactly how to escalate privileges
- **Exploitability scoring** - Rate findings by real-world exploitability

### IAM Deep Analysis

Understand your IAM attack surface with specialized analysis:

- **Privilege escalation paths** - PMapper graph analysis showing all paths to admin
- **Policy risk analysis** - Cloudsplaining identifies overly permissive policies
- **Assumed role chains** - Track role assumption paths across accounts
- **Lambda execution roles** - Identify functions with dangerous permissions
- **IMDS vulnerabilities** - Find EC2 instances vulnerable to metadata attacks

### Historical Tracking & Trends

Security posture over time, not just point-in-time snapshots:

- **Scan comparison** - See what's new, fixed, or unchanged between scans
- **MTTR metrics** - Mean Time To Remediation tracking
- **Trend analysis** - Track finding counts over time by severity
- **Remediation velocity** - Measure your security team's effectiveness

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Su1ph3r/Nubicustos.git
cd Nubicustos

# 2. Launch the stack
docker compose up -d

# 3. Access the web interface
open http://localhost:8080

# 4. Add credentials (via UI or mount)
mkdir -p credentials/aws
cp ~/.aws/credentials credentials/aws/
cp ~/.aws/config credentials/aws/

# 5. Run your first scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "aws_profile": "default"}'
```

> **Note:** Security tools run on-demand via Docker SDK - no need to pull 24+ images at startup.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              NUBICUSTOS                                      │
│                    Cloud Security Intelligence Platform                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │  SCAN ENGINE    │    │   ANALYSIS      │    │   PRESENTATION  │         │
│  │                 │    │                 │    │                 │         │
│  │ • 24+ Tools     │───▶│ • Normalization │───▶│ • Vue.js UI     │         │
│  │ • On-demand     │    │ • Attack Paths  │    │ • REST API      │         │
│  │ • Parallel Exec │    │ • Compliance    │    │ • MCP Server    │         │
│  │ • Error Track   │    │ • PoC Gen       │    │ • Exports       │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│           │                      │                      │                   │
│           └──────────────────────┼──────────────────────┘                   │
│                                  ▼                                          │
│                    ┌─────────────────────────┐                              │
│                    │      DATA LAYER         │                              │
│                    │                         │                              │
│                    │ PostgreSQL │ Neo4j      │                              │
│                    │ (Findings) │ (Graph)    │                              │
│                    └─────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Integrated Tools

| Category | Tools |
|----------|-------|
| **Cloud Security** | Prowler, ScoutSuite, CloudSploit, Pacu, CloudFox, Cloud Custodian |
| **AWS Deep Dive** | Enumerate-IAM, PMapper, Cloudsplaining, CloudMapper |
| **Kubernetes** | kube-bench, Kubescape, kube-hunter, Trivy, Grype, Polaris, Falco |
| **Secrets** | TruffleHog (700+ detectors), Gitleaks |
| **IaC Scanning** | Checkov, Terrascan, tfsec |
| **Asset Mapping** | Cartography (Neo4j graph) |

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

### Secrets Scanning
- **TruffleHog** - 700+ secret detectors with API verification
- **Gitleaks** - Fast git secrets scanner with extensive rule set

### IAM Deep Analysis
- **PMapper** - IAM privilege escalation path analysis
- **Cloudsplaining** - AWS managed policy analysis and least privilege violations

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

## Scan Profiles

| Profile | Duration | Description |
|---------|----------|-------------|
| `quick` | 5-10 min | Fast security assessment - Prowler only |
| `comprehensive` | 30-60 min | Full audit with all applicable tools |
| `compliance-only` | 15-20 min | Compliance-focused checks (Prowler + ScoutSuite) |
| `secrets` | 2-5 min | TruffleHog + Gitleaks secrets scanning |
| `iam-analysis` | 10-15 min | PMapper + Cloudsplaining IAM deep dive |
| `iac` | 2-5 min | Infrastructure-as-Code scanning |

```bash
# Via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "comprehensive", "aws_profile": "prod-audit"}'

# Via UI
# Navigate to Scans page → Quick Actions → Select profile → Start
```

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

### Secrets Scanning

```bash
# Scan for exposed secrets with TruffleHog and Gitleaks
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "secrets", "target_path": "/path/to/code"}'

# Query secrets findings
curl "http://localhost:8000/api/findings?tool=trufflehog"
curl "http://localhost:8000/api/findings?tool=gitleaks"
```

**Secrets Scanning Features:**
- **TruffleHog** - 700+ secret detectors with API verification for active credentials
- **Gitleaks** - Fast pattern-based detection with extensive rule coverage
- Automatic secret redaction in findings (only first 4 chars shown)
- Severity mapping: Verified secrets = Critical, Cloud provider keys = High

### IAM Deep Analysis

```bash
# Analyze IAM privilege escalation paths and policy risks
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "iam-analysis", "aws_profile": "your-profile"}'

# Query IAM findings
curl "http://localhost:8000/api/findings?tool=pmapper"
curl "http://localhost:8000/api/findings?tool=cloudsplaining"
```

**IAM Analysis Features:**
- **PMapper** - Graph-based IAM privilege escalation path discovery
- **Cloudsplaining** - Identifies least privilege violations in IAM policies
- Risk categories: Privilege Escalation, Resource Exposure, Data Exfiltration, Infrastructure Modification

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

### Bulk Operations

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

### Dynamic AWS Profiles

```bash
# Scan with specific AWS credential profile
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "comprehensive", "aws_profile": "prod-audit"}'

# List available AWS profiles
curl http://localhost:8000/api/credentials/aws/profiles
```

---

## API Highlights

```bash
# Get unified findings from all tools
curl "http://localhost:8000/api/findings?severity=critical,high"

# View attack paths with risk scores
curl http://localhost:8000/api/attack-paths

# Check compliance status
curl http://localhost:8000/api/compliance

# Export findings with remediation guidance
curl http://localhost:8000/api/exports/csv -o findings.csv

# Compare scans with MTTR metrics
curl "http://localhost:8000/api/scans/compare?baseline=abc123&current=def456"

# Get privilege escalation paths
curl http://localhost:8000/api/privesc-paths
```

Full API documentation available at `http://localhost:8000/docs` (Swagger UI).

---

## MCP Server for LLM Integration

Integrate Nubicustos with Claude, GPT, or other LLMs via the Model Context Protocol:

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

Ask natural language questions about your security posture:
- *"What are the most critical findings in my AWS account?"*
- *"Show me all privilege escalation paths to admin"*
- *"Are we compliant with CIS 2.0?"*
- *"What attack paths exist from public-facing resources?"*

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

See [MCP Server Guide](nubicustos-mcp/README.md) for setup instructions.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](INSTALL.md) | Detailed setup instructions |
| [Cheatsheet](CHEATSHEET.md) | Quick reference for common commands |
| [MCP Server Guide](nubicustos-mcp/README.md) | LLM integration via Model Context Protocol |
| [Architecture](STRUCTURE.md) | Detailed architecture documentation |
| [Contributing](CONTRIBUTING.md) | How to contribute to the project |
| [Changelog](CHANGELOG.md) | Version history and release notes |

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker Engine | 20.10+ | Latest |
| Docker Compose | 2.0+ | Latest |
| RAM | 16GB | 32GB |
| Disk Space | 50GB | 100GB |

---

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 8080 | Nginx | Web frontend |
| 8000 | FastAPI | REST API |
| 5432 | PostgreSQL | Findings database |
| 7474 | Neo4j HTTP | Graph browser |
| 7687 | Neo4j Bolt | Graph queries |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Security

Found a vulnerability? Please use GitHub's private vulnerability reporting or email maintainers directly. Do not open public issues for security concerns.

### Security Features

- **Path Traversal Protection** - All file operations validated with `os.path.realpath()` to prevent directory escape
- **Zip Slip Prevention** - Archive extraction secured against path manipulation attacks
- **ReDoS Mitigation** - Input length limits on regex patterns to prevent denial of service
- **Log Sanitization** - Credentials, tokens, and IP addresses automatically redacted from logs
- **Error Information Control** - Limited validation error details to prevent schema disclosure
- **SQLAlchemy Error Handling** - Specific exception handling to prevent information leakage

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Nubicustos builds on these excellent open-source security tools:

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
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets detection with verification | AGPL-3.0 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Git secrets scanner | MIT |
| [PMapper](https://github.com/nccgroup/PMapper) | IAM privilege escalation analysis | AGPL-3.0 |
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | AWS IAM policy analysis | BSD-3-Clause |

See [NOTICE](NOTICE) for full attribution.

---

## Roadmap

- [ ] IBM Cloud support
- [ ] SIEM platform integration
- [ ] Slack/Teams notifications
- [ ] Automated scheduled scanning
- [ ] Multi-tenancy support

---

<p align="center">
  <strong>Turn security scanner noise into actionable intelligence.</strong>
</p>
