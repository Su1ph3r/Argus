# Nubicustos Wiki

Welcome to the Nubicustos documentation wiki. This wiki provides comprehensive documentation for the cloud security auditing platform.

## Quick Navigation

### Getting Started
- [[Installation Guide|INSTALL]] - Quick setup in 5 minutes
- [[Deployment Guide|DEPLOYMENT]] - Production deployment instructions
- [[Command Cheatsheet|CHEATSHEET]] - Quick reference for common commands

### Core Features
- [[Scan Orchestration|Scan-Orchestration]] - How the scan system works
- [[Security Tools Reference|Security-Tools-Reference]] - All supported scanning tools
- [[Bulk Operations|Bulk-Operations]] - Multi-select, bulk delete, and archive (v1.0.2)
- [[Error Tracking|Error-Tracking]] - Per-tool error analysis (v1.0.2)
- [[Attack Path Analysis|Attack-Path-Analysis]] - Graph-based attack chain discovery
- [[AWS Security Analysis|AWS-Security-Analysis]] - IMDS checks, Lambda analysis, privilege escalation

### User Interfaces
- [[Web Frontend|Web-Frontend]] - Vue.js 3 dashboard with 22+ views
- [[MCP Server Integration|MCP-Server-Integration]] - LLM integration via Model Context Protocol

### API Reference
- [[REST API Overview|API]] - Complete API documentation (scans, findings, attack paths, bulk operations)

### Architecture
- [[System Architecture|ARCHITECTURE]] - Technical architecture overview

### Security
- [[Security Analysis|Security-Analysis]] - Security considerations and best practices
- [[Security Policy|SECURITY]] - Vulnerability reporting process

### Development
- [[Contributing|CONTRIBUTING]] - How to contribute to the project
- [[Code Structure|STRUCTURE]] - Repository organization

---

## What is Nubicustos?

Nubicustos is a Docker Compose-based platform for automated cloud security auditing across AWS, Azure, GCP, and Kubernetes environments. It orchestrates 20+ security scanning tools and provides:

- **Vue.js 3 Web Frontend** with 22+ specialized views for findings, attack paths, and compliance
- **MCP Server** for LLM integration via Model Context Protocol (Claude Desktop, Ollama)
- **Attack Path Analysis** with graph-based discovery and MITRE ATT&CK mapping
- **REST API** with 20+ endpoint groups for programmatic access
- **PostgreSQL database** for centralized findings storage
- **Neo4j graph database** for asset relationship mapping
- **Remediation Knowledge Base** with AWS CLI commands and guidance

## Key Features

### Multi-Cloud Support
- **AWS**: Prowler, ScoutSuite, CloudFox, Enumerate-IAM, Pacu, CloudSploit, Cloud Custodian, CloudMapper, Cartography
- **Azure**: ScoutSuite, CloudSploit, Cloud Custodian
- **GCP**: Prowler, ScoutSuite, CloudSploit, Cartography
- **Kubernetes**: kube-bench, Kubescape, kube-hunter, Trivy, and more

### AWS Security Deep-Dive
- **IMDS Checks** - EC2 metadata service vulnerabilities
- **Lambda Analysis** - Serverless security assessment
- **Privilege Escalation Paths** - IAM lateral movement discovery
- **Exposed Credentials** - Credential leak detection
- **Public Exposures** - Attack surface monitoring
- **Assumed Roles** - Cross-account role analysis

### Scan Profiles
| Profile | Duration | Tools | Use Case |
|---------|----------|-------|----------|
| Quick | 5-10 min | Prowler | Fast security posture check |
| Comprehensive | 30-60 min | All AWS tools | Full security audit |
| Compliance-Only | 15-20 min | Prowler + ScoutSuite | Compliance framework scanning |

### Docker SDK Integration
The scan orchestration system uses direct Docker SDK calls for reliable container management:
- Sequential tool execution with proper completion detection
- Automatic handling of security tool exit codes
- Report processing with attack path analysis
- Container lifecycle management

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Su1ph3r/Nubicustos.git
cd Nubicustos

# Start the stack
docker compose up -d

# Access the web interface
open http://localhost:8080

# Or trigger a scan via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "aws_profile": "default"}'
```

## Service Ports

| Port | Service | Description |
|------|---------|-------------|
| 8080 | Nginx | Vue.js web frontend |
| 8000 | FastAPI | REST API (20+ endpoint groups) |
| 5432 | PostgreSQL | Findings database |
| 7474/7687 | Neo4j | Asset graph database |

## Support

- **Issues**: [GitHub Issues](https://github.com/Su1ph3r/Nubicustos/issues)
- **Security**: See [[Security Policy|SECURITY]] for vulnerability reporting
- **Contributing**: See [[Contributing Guide|CONTRIBUTING]]

---

*Nubicustos - Cloud Security Auditing Made Simple*
