# Attack Path Analysis

Nubicustos automatically discovers and analyzes attack paths through your cloud infrastructure, helping you understand how attackers could move laterally from initial access to high-value targets.

## Overview

The attack path analyzer examines security findings and asset relationships to identify multi-step attack chains. Each path includes:

- **Entry points** - Where attackers could gain initial access
- **Intermediate steps** - Lateral movement opportunities
- **Target resources** - High-value assets at risk
- **MITRE ATT&CK mapping** - Tactics and techniques
- **Risk scoring** - Exploitability and impact ratings
- **PoC commands** - AWS CLI commands to verify findings

## How It Works

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Security       │    │  Attack Path    │    │  PostgreSQL     │
│  Findings       │───▶│  Analyzer       │───▶│  Database       │
│  (Prowler, etc) │    │                 │    │  (attack_paths) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Neo4j Graph    │
                       │  (Cartography)  │
                       └─────────────────┘
```

1. Security tools generate findings
2. Report processor loads findings to PostgreSQL
3. Attack path analyzer queries findings and asset relationships
4. Graph-based algorithm discovers multi-step paths
5. Paths stored with nodes, edges, and risk scores

## Attack Path Model

### Path Structure

```json
{
  "id": "path-abc123",
  "name": "Public S3 to IAM Admin",
  "description": "Attacker could exploit public S3 bucket...",
  "severity": "critical",
  "exploitability_score": 85,
  "impact_score": 95,
  "mitre_tactics": ["initial-access", "privilege-escalation"],
  "mitre_techniques": ["T1190", "T1078"],
  "nodes": [...],
  "edges": [...],
  "poc_steps": [...]
}
```

### Nodes

Each node represents an asset or finding in the path:

```json
{
  "id": "node-1",
  "type": "finding",
  "resource_type": "s3_bucket",
  "resource_id": "arn:aws:s3:::company-data",
  "finding_id": "finding-xyz",
  "severity": "high"
}
```

### Edges

Edges connect nodes and describe the attack technique:

```json
{
  "source": "node-1",
  "target": "node-2",
  "attack_type": "credential_exposure",
  "description": "Leaked AWS credentials in bucket policy",
  "mitre_technique": "T1552.001"
}
```

### PoC Steps

Proof-of-concept commands to verify the path:

```json
{
  "step": 1,
  "description": "List public bucket contents",
  "command": "aws s3 ls s3://company-data --no-sign-request",
  "expected_result": "Bucket contents visible without authentication"
}
```

## Risk Scoring

### Exploitability Score (0-100)

Measures how easily the path can be exploited:

| Factor | Weight | Description |
|--------|--------|-------------|
| Public accessibility | 30% | Is the entry point internet-facing? |
| Authentication required | 25% | Are credentials needed? |
| Complexity | 20% | Number of steps required |
| Tool availability | 15% | Are exploitation tools available? |
| Detection likelihood | 10% | Will the attack be detected? |

### Impact Score (0-100)

Measures potential damage if exploited:

| Factor | Weight | Description |
|--------|--------|-------------|
| Data sensitivity | 35% | Type of data at risk |
| Resource criticality | 25% | Business importance |
| Blast radius | 20% | How many resources affected |
| Recovery difficulty | 20% | Time to remediate |

## MITRE ATT&CK Integration

Attack paths are mapped to MITRE ATT&CK framework:

### Tactics
- `initial-access` - How attackers gain entry
- `execution` - Running malicious code
- `persistence` - Maintaining access
- `privilege-escalation` - Gaining higher privileges
- `credential-access` - Stealing credentials
- `lateral-movement` - Moving through the environment

### Techniques
- `T1190` - Exploit Public-Facing Application
- `T1078` - Valid Accounts
- `T1552` - Unsecured Credentials
- `T1484` - Domain Policy Modification
- `T1087` - Account Discovery

## API Endpoints

### List Attack Paths

```bash
curl http://localhost:8000/api/attack-paths
```

Query parameters:
- `severity` - Filter by severity (critical, high, medium, low)
- `min_impact` - Minimum impact score (0-100)
- `mitre_tactic` - Filter by MITRE tactic
- `limit` - Number of results (default: 50)

### Get Path Details

```bash
curl http://localhost:8000/api/attack-paths/path-abc123
```

Returns full path with nodes, edges, and PoC steps.

### Analyze Paths

Trigger path analysis for recent findings:

```bash
curl -X POST http://localhost:8000/api/attack-paths/analyze \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "scan-xyz"}'
```

## Web Frontend

The Attack Paths view provides:

- **Path list** with severity and scores
- **Graph visualization** of attack chains
- **Node details** on click
- **PoC command** copy-to-clipboard
- **Export** to JSON/PDF

Access at `http://localhost:8080/attack-paths`

## Common Attack Patterns

### Public Bucket to IAM Compromise
1. Public S3 bucket discovered
2. Credentials found in bucket
3. Credentials used to assume role
4. Role has admin privileges

### IMDS to Account Takeover
1. EC2 instance with IMDSv1
2. SSRF vulnerability exploited
3. Instance role credentials obtained
4. Role allows privilege escalation

### Lambda to Data Exfiltration
1. Lambda with overprivileged role
2. Environment variables expose secrets
3. Secrets grant database access
4. Sensitive data accessed

## Remediation Priority

Attack paths help prioritize remediation:

1. **Critical paths** (impact > 80) - Immediate action
2. **High severity entry points** - Block initial access
3. **Privilege escalation nodes** - Limit blast radius
4. **Data exposure targets** - Protect sensitive assets

## Configuration

Configure the analyzer in `report-processor/attack_path_analyzer.py`:

```python
# Minimum finding severity to include
MIN_SEVERITY = "medium"

# Maximum path depth
MAX_PATH_DEPTH = 5

# Edge types to consider
EDGE_TYPES = [
    "credential_exposure",
    "role_assumption",
    "permission_escalation",
    "network_access",
    "data_access"
]
```

---

*See also: [[Security Tools Reference|Security-Tools-Reference]], [[REST API Overview|API]]*
