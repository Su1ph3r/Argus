# Security Tools Reference

This document provides comprehensive documentation for all security scanning tools supported by Nubicustos.

## AWS Security Tools

### Prowler

**Purpose**: AWS compliance and security scanning with support for 300+ checks across CIS, PCI-DSS, SOC2, HIPAA, and more.

| Property | Value |
|----------|-------|
| Image | `toniblyx/prowler:4.2.4` |
| Output Formats | JSON-OCSF, HTML, CSV |
| Expected Exit Codes | 0 (no findings), 1 (findings detected), 3 (findings + check errors) |

**Default Command**:
```bash
prowler aws --output-formats json-ocsf html csv --output-directory /reports
```

**Profile Options**:
- Quick: `--severity critical high`
- Compliance: `--compliance cis_2.0_aws soc2_aws pci_dss_v4.0_aws`

**Supported Compliance Frameworks**:
- CIS AWS Foundations Benchmark v2.0
- PCI-DSS v4.0
- SOC2
- HIPAA
- NIST 800-53
- AWS Well-Architected Framework

---

### ScoutSuite

**Purpose**: Multi-cloud security auditing for AWS, Azure, GCP, and Alibaba Cloud.

| Property | Value |
|----------|-------|
| Image | `opendevsecops/scoutsuite:5.12.0` |
| Output Formats | HTML, JSON |
| Expected Exit Codes | 0 (success), 1 (findings detected) |

**Default Command**:
```bash
scout aws --no-browser --report-dir /reports
```

**Profile Options**:
- Compliance: `--ruleset cis`

**Features**:
- Interactive HTML reports with severity filtering
- Service-by-service breakdown
- Historical comparison support

---

### CloudFox

**Purpose**: AWS attack surface enumeration for penetration testers and red teams.

| Property | Value |
|----------|-------|
| Image | `bishopfox/cloudfox:1.14.2` |
| Output Formats | Text, CSV |
| Expected Exit Codes | 0 (success), 1 (findings detected) |

**Default Command**:
```bash
cloudfox aws all-checks --output /reports
```

**Key Checks**:
- IAM privilege escalation paths
- Lambda function analysis
- EC2 instance metadata service (IMDS) exposure
- S3 bucket permissions
- Secrets in environment variables
- Network exposure analysis

---

### CloudSploit

**Purpose**: AWS security configuration scanning with remediation guidance.

| Property | Value |
|----------|-------|
| Image | `cloudsploit:local` (custom build) |
| Output Formats | JSON, CSV |
| Expected Exit Codes | 0 (success), 1 (findings detected), 2 (errors) |

**Default Command**:
```bash
node index.js --compliance=hipaa --csv=/reports/cloudsploit.csv --json=/reports/cloudsploit.json
```

**Features**:
- 300+ security checks
- Compliance mapping (HIPAA, PCI, CIS)
- Remediation recommendations
- Multi-cloud support (AWS, Azure, GCP, OCI)

---

### Cloud Custodian

**Purpose**: Policy-as-code rules engine for cloud resource management and compliance.

| Property | Value |
|----------|-------|
| Image | `cloudcustodian/c7n:0.9.34` |
| Output Formats | JSON |
| Expected Exit Codes | 0 (success), 1 (policy violations) |

**Default Command**:
```bash
custodian run -s /reports /policies/security-policies.yml
```

**Features**:
- Custom policy definitions in YAML
- Real-time compliance enforcement
- Cost optimization policies
- Automated remediation actions

**Example Policy**:
```yaml
policies:
  - name: ec2-public-ingress
    resource: ec2
    filters:
      - type: security-group
        key: IpPermissions[].IpRanges[].CidrIp
        value: "0.0.0.0/0"
```

---

### CloudMapper

**Purpose**: AWS account visualization and network topology mapping.

| Property | Value |
|----------|-------|
| Image | `cloudmapper:local` (custom build) |
| Output Formats | HTML, JSON, SVG |
| Expected Exit Codes | 0 (success) |

**Commands**:
```bash
# Collect AWS account data
cloudmapper collect --account myaccount

# Generate network diagram
cloudmapper prepare --account myaccount
cloudmapper webserver --public
```

**Features**:
- Interactive network topology diagrams
- Public exposure analysis
- Security group visualization
- VPC peering relationships

---

### Cartography

**Purpose**: Asset relationship graphing and infrastructure mapping to Neo4j.

| Property | Value |
|----------|-------|
| Image | `ghcr.io/lyft/cartography:0.94.0` |
| Output | Neo4j graph database |
| Expected Exit Codes | 0 (success) |

**Default Command**:
```bash
cartography --neo4j-uri bolt://neo4j:7687 --neo4j-user neo4j --neo4j-password-env-var NEO4J_PASSWORD
```

**Features**:
- Asset inventory in graph format
- Relationship mapping (EC2 → Security Groups → VPCs)
- Attack path analysis queries
- Integration with Neo4j Browser

**Example Cypher Queries**:
```cypher
// Find all public EC2 instances
MATCH (e:EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
WHERE sg.ingress_allows_all = true
RETURN e.id, e.publicipaddress

// Find IAM users without MFA
MATCH (u:AWSUser)
WHERE u.mfa_active = false
RETURN u.name, u.arn
```

---

## Penetration Testing Tools

### Pacu

**Purpose**: AWS exploitation framework for authorized penetration testing.

| Property | Value |
|----------|-------|
| Image | `rhinosecuritylabs/pacu:1.6.0` |
| Output | Session logs, JSON |
| Expected Exit Codes | 0 (success) |

**WARNING**: This tool performs active exploitation. Only use with proper authorization.

**Default Command**:
```bash
pacu --use-default-session
```

**Modules Include**:
- IAM privilege escalation
- Lambda backdoors
- EC2 instance compromise
- Persistence mechanisms

---

### enumerate-iam

**Purpose**: IAM permission enumeration through brute-force API calls.

| Property | Value |
|----------|-------|
| Image | `enumerate-iam:local` (custom build) |
| Output | Text, JSON |
| Expected Exit Codes | 0 (success), 1 (partial enumeration) |

**Default Command**:
```bash
python enumerate-iam.py --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY
```

**Features**:
- Discovers actual IAM permissions
- Bypasses IAM policy simulation limitations
- Identifies hidden permissions

---

## Kubernetes Security Tools

### Kubescape

**Purpose**: Kubernetes security scanning for NSA, MITRE ATT&CK, and CIS benchmarks.

| Property | Value |
|----------|-------|
| Image | `quay.io/armosec/kubescape:v3.0.8` |
| Output Formats | JSON, HTML, SARIF |
| Expected Exit Codes | 0 (success), 1 (findings detected) |

**Default Command**:
```bash
kubescape scan --format json --output /reports/kubescape.json
```

**Supported Frameworks**:
- NSA-CISA Kubernetes Hardening Guidance
- MITRE ATT&CK for Containers
- CIS Kubernetes Benchmark
- DevOpsBest practices

---

## Tool Exit Code Reference

Security scanning tools commonly return non-zero exit codes when findings are detected. This is expected behavior:

| Tool | Exit 0 | Exit 1 | Exit 2 | Exit 3 |
|------|--------|--------|--------|--------|
| Prowler | No findings | Findings detected | - | Findings + errors |
| ScoutSuite | Success | Findings detected | - | - |
| CloudFox | Success | Findings detected | - | - |
| CloudSploit | Success | Findings detected | Errors | - |
| Cloud Custodian | Success | Policy violations | - | - |
| Kubescape | Success | Findings detected | - | - |

The orchestration system checks exit codes against each tool's `expected_exit_codes` configuration to determine success or failure.

---

## Volume Mount Reference

All tools use consistent volume mounting patterns:

| Mount Point | Purpose | Access |
|-------------|---------|--------|
| `/reports` | Output directory | Read/Write |
| `/home/{tool}/.aws` | AWS credentials | Read-Only |
| `/policies` | Policy definitions | Read-Only |

---

## Network Configuration

All security tools run on the `nubicustos_security-net` Docker network, providing:
- Database connectivity (PostgreSQL, Neo4j)
- Inter-container communication
- Isolation from external networks

---

*For scan orchestration details, see [[Scan Orchestration|Scan-Orchestration]].*
*For API documentation, see [[REST API Overview|API]].*
