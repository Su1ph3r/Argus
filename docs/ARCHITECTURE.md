# Nubicustos Architecture

This document provides a comprehensive overview of the Nubicustos cloud security auditing platform architecture.

## System Overview

Nubicustos is a Docker Compose-based platform that orchestrates 20+ security scanning tools to provide automated cloud security auditing across AWS, Azure, GCP, and Kubernetes environments.

```
                                    +-------------------+
                                    |   User/Operator   |
                                    +--------+----------+
                                             |
              +------------------------------+------------------------------+
              |                              |                              |
              v                              v                              v
    +------------------+          +------------------+          +------------------+
    |  Nginx (:8080)   |          |  REST API (:8000)|          |  Neo4j (:7474)   |
    |  Vue.js Frontend |          |  FastAPI + Uvicorn|         |  Asset Graph     |
    +--------+---------+          +--------+---------+          +--------+---------+
             |                             |                             |
             |                             v                             |
             |                    +------------------+                   |
             |                    |   PostgreSQL     |<------------------+
             |                    |   (:5432)        |
             |                    +--------+---------+
             |                             ^
             v                             |
    +------------------+          +--------+---------+
    |     reports/     |          | Report Processor |
    |  (HTML/JSON/CSV) |<---------| Python Scripts   |
    +------------------+          +--------+---------+
                                           ^
              +----------------------------+----------------------------+
              |              |             |             |              |
              v              v             v             v              v
    +----------+   +----------+   +----------+   +----------+   +----------+
    | Prowler  |   |ScoutSuite|   |Kubescape |   | Checkov  |   | Trivy    |
    +----------+   +----------+   +----------+   +----------+   +----------+
         |              |              |              |              |
         v              v              v              v              v
    +-----------------------------------------------------------------------+
    |                         Cloud Provider APIs                            |
    |   (AWS, Azure, GCP)           Kubernetes API                          |
    +-----------------------------------------------------------------------+
```

## Service Layer Architecture

### Docker Compose Services

The platform is organized into functional layers:

```
docker-compose.yml
|
+-- Security Scanning Tools
|   +-- AWS Tools
|   |   +-- prowler          (AWS security best practices)
|   |   +-- scoutsuite       (Multi-cloud auditor)
|   |   +-- pacu             (AWS exploitation framework)
|   |   +-- cloudsploit      (Cloud security scanner)
|   |   +-- cloud-custodian  (Policy enforcement)
|   |   +-- cartography      (Asset relationship mapping)
|   |
|   +-- Kubernetes Tools
|   |   +-- kube-bench       (CIS benchmark checker)
|   |   +-- kubescape        (NSA/MITRE hardening)
|   |   +-- popeye           (Cluster sanitizer)
|   |   +-- kube-linter      (Manifest linter)
|   |   +-- polaris          (Best practices validator)
|   |   +-- falco            (Runtime security)
|   |
|   +-- Container Scanners
|   |   +-- trivy            (Vulnerability scanner)
|   |   +-- grype            (Image scanner)
|   |
|   +-- IaC Scanners
|       +-- checkov          (Terraform/CloudFormation)
|       +-- terrascan        (IaC security)
|       +-- tfsec            (Terraform security)
|
+-- Data Storage
|   +-- postgresql           (Findings database)
|   +-- neo4j                (Asset graph database)
|
+-- Web Services
|   +-- api                  (FastAPI REST service)
|   +-- nginx                (Vue.js frontend hosting)
|
+-- Report Processing
    +-- report-processor     (Python parsing/loading scripts)
```

## Data Flow

### 1. Scan Execution Flow

```
+-------------+     +----------------+     +------------------+
|   Operator  | --> | run-all-audits | --> | Docker Compose   |
| CLI/API     |     | .sh            |     | Tool Containers  |
+-------------+     +----------------+     +--------+---------+
                                                    |
                                                    v
                                          +------------------+
                                          | Cloud Provider   |
                                          | APIs             |
                                          +--------+---------+
                                                   |
                                                   v
                                          +------------------+
                                          | reports/{tool}/  |
                                          | JSON/HTML/CSV    |
                                          +------------------+
```

### 2. Report Processing Flow

```
+------------------+     +------------------+     +------------------+
| reports/{tool}/  | --> | process_reports  | --> | PostgreSQL       |
| JSON files       |     | .py              |     | findings table   |
+------------------+     +--------+---------+     +------------------+
                                  |
                                  v
                         +------------------+
                         | attack_path_     |
                         | analyzer.py      |
                         +--------+---------+
                                  |
                                  v
                         +------------------+
                         | attack_paths     |
                         | table            |
                         +------------------+
```

### 3. Asset Mapping Flow (Cartography)

```
+------------------+     +------------------+     +------------------+
| Cloud APIs       | --> | Cartography      | --> | Neo4j            |
| (AWS/Azure/GCP)  |     | Container        |     | Graph Database   |
+------------------+     +------------------+     +------------------+
                                                          |
                                                          v
                                                 +------------------+
                                                 | Asset Graph      |
                                                 | Relationships    |
                                                 +------------------+
```

### 4. API Request Flow

```
+-------------+     +------------------+     +------------------+
|   Client    | --> | Nginx            | --> | FastAPI          |
| (HTTP)      |     | (Reverse Proxy)  |     | (Uvicorn)        |
+-------------+     +------------------+     +--------+---------+
                                                      |
                         +----------------------------+
                         |                            |
                         v                            v
               +------------------+          +------------------+
               | PostgreSQL       |          | Neo4j            |
               | (Findings)       |          | (Assets)         |
               +------------------+          +------------------+
```

## Database Schema

### PostgreSQL Tables

#### Core Tables

**scans**
```sql
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    scan_id UUID UNIQUE NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    target VARCHAR(255),
    tool VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**findings**
```sql
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    finding_id VARCHAR(255) NOT NULL,
    canonical_id VARCHAR(255),
    scan_id UUID REFERENCES scans(scan_id),
    tool VARCHAR(100) NOT NULL,
    cloud_provider VARCHAR(50),
    account_id VARCHAR(100),
    region VARCHAR(100),
    resource_type VARCHAR(255),
    resource_id VARCHAR(512),
    resource_name VARCHAR(512),
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    title TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    compliance_mappings JSONB,
    risk_score DECIMAL(5,2),
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(50),
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    scan_date TIMESTAMP WITH TIME ZONE,
    tags JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**attack_paths**
```sql
CREATE TABLE attack_paths (
    id SERIAL PRIMARY KEY,
    path_id VARCHAR(32) UNIQUE NOT NULL,
    scan_id UUID,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    entry_point_type VARCHAR(100),
    entry_point_id VARCHAR(512),
    entry_point_name VARCHAR(255),
    target_type VARCHAR(100),
    target_description TEXT,
    nodes JSONB,
    edges JSONB,
    finding_ids JSONB,
    risk_score INTEGER,
    exploitability VARCHAR(50),
    impact VARCHAR(50),
    hop_count INTEGER,
    requires_authentication BOOLEAN DEFAULT FALSE,
    requires_privileges BOOLEAN DEFAULT FALSE,
    poc_available BOOLEAN DEFAULT FALSE,
    poc_steps JSONB,
    mitre_tactics JSONB,
    aws_services JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**assets**
```sql
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    asset_id VARCHAR(512) UNIQUE NOT NULL,
    cloud_provider VARCHAR(50),
    account_id VARCHAR(100),
    region VARCHAR(100),
    resource_type VARCHAR(255),
    resource_name VARCHAR(512),
    tags JSONB,
    metadata JSONB,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE
);
```

#### Key Views

**recent_findings_summary**
```sql
CREATE VIEW recent_findings_summary AS
SELECT
    tool,
    cloud_provider,
    severity,
    COUNT(*) as count
FROM findings
WHERE scan_date > NOW() - INTERVAL '7 days'
GROUP BY tool, cloud_provider, severity;
```

**open_findings_by_severity**
```sql
CREATE VIEW open_findings_by_severity AS
SELECT
    severity,
    COUNT(*) as count
FROM findings
WHERE status IN ('open', 'fail')
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END;
```

### Neo4j Graph Structure

Cartography populates Neo4j with cloud asset relationships:

#### Node Types

```
(:AWSAccount)
(:EC2Instance)
(:S3Bucket)
(:IAMUser)
(:IAMRole)
(:IAMPolicy)
(:SecurityGroup)
(:VPC)
(:Subnet)
(:RDSInstance)
(:LambdaFunction)
(:EKSCluster)
(:KubernetesCluster)
(:Pod)
(:Container)
```

#### Relationship Types

```
(AWSAccount)-[:RESOURCE]->(EC2Instance)
(EC2Instance)-[:MEMBER_OF_SECURITY_GROUP]->(SecurityGroup)
(EC2Instance)-[:PART_OF_SUBNET]->(Subnet)
(Subnet)-[:MEMBER_OF_VPC]->(VPC)
(IAMUser)-[:HAS_POLICY]->(IAMPolicy)
(IAMRole)-[:TRUSTS]->(AWSAccount)
(IAMRole)-[:CAN_ASSUME]->(IAMRole)
(S3Bucket)-[:HAS_POLICY]->(S3BucketPolicy)
```

#### Example Cypher Queries

**Find publicly accessible S3 buckets:**
```cypher
MATCH (b:S3Bucket)
WHERE b.anonymous_access = true
RETURN b.name, b.arn
```

**Find EC2 instances with IAM roles that can assume other roles:**
```cypher
MATCH (i:EC2Instance)-[:STS_ASSUME_ROLE_ALLOW]->(r:IAMRole)-[:CAN_ASSUME]->(target:IAMRole)
RETURN i.instanceid, r.name, target.name
```

## Component Details

### REST API (api/)

The API is built with FastAPI and provides:

**Structure:**
```
api/
+-- main.py              # FastAPI app, middleware, router registration
+-- config.py            # Pydantic settings from environment
+-- logging_config.py    # Structured logging configuration
+-- models/
|   +-- database.py      # SQLAlchemy ORM models
|   +-- schemas.py       # Pydantic request/response schemas
+-- routers/
    +-- health.py        # Health check endpoints
    +-- scans.py         # Scan management
    +-- findings.py      # Findings CRUD
    +-- exports.py       # Data export
    +-- attack_paths.py  # Attack path analysis
```

**Key Features:**
- Async request handling with Uvicorn
- CORS configuration for web frontends
- Optional API key authentication
- Structured JSON logging
- OpenAPI/Swagger documentation

### Report Processor (report-processor/)

Python scripts for parsing and loading scan results:

**Scripts:**
```
report-processor/
+-- process_reports.py       # Main report processing orchestrator
+-- compare_scans.py         # Scan diff and trend analysis
+-- attack_path_analyzer.py  # Attack graph construction and BFS
+-- attack_path_edges.py     # Edge definitions for path finding
+-- parsers/
    +-- prowler_parser.py
    +-- scoutsuite_parser.py
    +-- kubescape_parser.py
    +-- (etc.)
```

### Scan Profiles (profiles/)

YAML configuration files for scan presets:

**Structure:**
```yaml
# profiles/comprehensive.yml
name: comprehensive
description: Full security audit with all tools enabled
estimated_duration: 30-60 minutes

tools:
  aws:
    prowler:
      enabled: true
      options:
        output_modes: "json,html"
        severity: "critical,high,medium,low"
    scoutsuite:
      enabled: true
      options:
        report_format: "json"

  kubernetes:
    kubescape:
      enabled: true
      options:
        frameworks: "nsa,mitre,cis"
    kube-bench:
      enabled: true
      options:
        benchmark: "cis-1.8"

  iac:
    checkov:
      enabled: true
      options:
        framework: "all"
```

### Attack Path Analysis

The attack path analyzer discovers chains of vulnerabilities:

**Algorithm:**
1. Load security findings from PostgreSQL
2. Map findings to graph edges using `attack_path_edges.py` definitions
3. Build attack graph with:
   - Entry points (public exposure, weak credentials)
   - Resource nodes (findings locations)
   - Target nodes (account takeover, data exfiltration, etc.)
4. BFS from each entry point to discover paths to targets
5. Score paths using CVSS-inspired methodology
6. Store discovered paths in `attack_paths` table

**Risk Score Calculation (0-100):**
- Based on CVSS 3.1 concepts
- Impact score from target criticality
- Exploitability from attack vector, complexity, privileges required
- Adjusted for confirmation level (confirmed, likely, theoretical)

## Port Mappings

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Nginx | 8080 | HTTP | Vue.js web frontend |
| FastAPI | 8000 | HTTP | REST API |
| PostgreSQL | 5432 | TCP | Findings database |
| Neo4j HTTP | 7474 | HTTP | Neo4j browser |
| Neo4j Bolt | 7687 | TCP | Neo4j driver protocol |

## Volume Mounts

| Volume | Container Path | Purpose |
|--------|----------------|---------|
| ./reports | /reports | Scan output storage |
| ./credentials | /credentials | Cloud provider credentials |
| ./kubeconfigs | /kubeconfigs | Kubernetes configs |
| ./profiles | /profiles | Scan profile configs |
| ./data/postgresql | /var/lib/postgresql/data | Database persistence |
| ./data/neo4j | /data | Graph database persistence |

## Security Considerations

### Credential Handling
- Credentials stored in `credentials/` directory (gitignored)
- Mounted read-only into scanning containers
- Environment variables for database passwords
- API key authentication optional

### Network Isolation
- Scanning tools run in isolated containers
- Database ports can be restricted to internal network
- Nginx provides reverse proxy protection

### Secrets Management
- `.env` file for sensitive configuration (gitignored)
- Docker secrets support for Swarm deployments
- Vault integration possible via environment variables

## Extending the Platform

### Adding a New Scanning Tool

1. Add service definition to `docker-compose.yml`:
```yaml
new-tool:
  image: vendor/new-tool:latest
  volumes:
    - ./credentials:/credentials:ro
    - ./reports/new-tool:/output
  environment:
    - ENABLE_NEW_TOOL=${ENABLE_NEW_TOOL:-true}
```

2. Create report directory:
```bash
mkdir reports/new-tool
```

3. Add ENABLE variable to `.env.example`

4. Update `scripts/run-all-audits.sh` to include the tool

5. Create parser in `report-processor/parsers/`:
```python
def parse_new_tool_report(report_path):
    # Parse JSON/CSV/XML output
    # Return standardized finding dicts
    pass
```

6. Register parser in `process_reports.py`

### Extending the API

1. Create new router in `api/routers/`
2. Register in `api/main.py`:
```python
from routers import new_router
app.include_router(new_router.router, prefix="/api")
```
3. Add models to `api/models/schemas.py`
