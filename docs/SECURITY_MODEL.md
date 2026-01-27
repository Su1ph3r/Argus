# Nubicustos Security Model

This document describes the security architecture, threat model, and security controls implemented in Nubicustos.

## Table of Contents

- [Threat Model Overview](#threat-model-overview)
- [Findings Data Protection](#findings-data-protection)
- [API Authentication](#api-authentication)
- [Credential Handling](#credential-handling)
- [Log Sanitization](#log-sanitization)

---

## Threat Model Overview

### System Scope

Nubicustos is a security auditing platform that:
- Stores cloud security findings (potentially sensitive vulnerability data)
- Manages cloud provider credentials (AWS, Azure, GCP access)
- Exposes REST API for findings access
- Runs privileged containers with Docker socket access

### Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| External Attacker | Network access | Data theft, reconnaissance |
| Malicious Insider | Authenticated API access | Privilege escalation, data exfiltration |
| Compromised Tool | Container execution | Lateral movement, credential theft |
| Supply Chain | Malicious image/dependency | Backdoor, data theft |

### Assets at Risk

| Asset | Sensitivity | Impact if Compromised |
|-------|-------------|----------------------|
| Cloud credentials | Critical | Full cloud account compromise |
| Security findings | High | Reveals vulnerabilities to attackers |
| Attack paths | High | Provides exploitation roadmap |
| API keys | Medium | Unauthorized API access |
| Scan logs | Low-Medium | May contain resource names |

### Trust Boundaries

```
                                    TRUST BOUNDARY
                                         |
    Internet                             |         Internal Network
    --------                             |         ----------------
                                         |
    [Attacker] ----X----> [Nginx] ------|-----> [API] ----> [PostgreSQL]
                                         |            \
                                         |             ---> [Neo4j]
                                         |            \
                                         |             ---> [Docker Socket]
                                         |                      |
                                         |              [Scan Containers]
                                         |                      |
                                         |              [Cloud Provider APIs]
```

### Attack Vectors

1. **Network-based attacks**
   - API exploitation (injection, SSRF)
   - Container escape via Docker socket
   - Database credential theft

2. **Authentication bypass**
   - API key theft or brute force
   - Session hijacking (if web auth added)

3. **Data exfiltration**
   - Findings export abuse
   - Log file access
   - Container volume exposure

4. **Supply chain attacks**
   - Malicious tool images
   - Dependency vulnerabilities

---

## Findings Data Protection

### Data Classification

| Data Type | Classification | Handling |
|-----------|---------------|----------|
| Finding titles/descriptions | Confidential | Access-controlled |
| Resource IDs/ARNs | Confidential | Access-controlled |
| Remediation steps | Internal | Access-controlled |
| Attack paths with PoC | Highly Confidential | Restricted access |
| Compliance mappings | Internal | Access-controlled |
| Scan metadata | Internal | Logged |

### Access Control

**Current Implementation:**
- API key authentication (optional, configurable)
- All endpoints require same access level
- No role-based access control (RBAC) currently

**Recommended Production Configuration:**

```bash
# Enable API authentication
API_KEY=$(openssl rand -hex 32)
echo "API_KEY=${API_KEY}" >> .env
```

**Future Enhancement Roadmap:**
- Role-based access (admin, viewer, operator)
- Per-resource access control
- Audit logging of data access

### Data at Rest

**PostgreSQL:**
- Data stored in Docker volume `postgres-data`
- Encryption at rest depends on host disk encryption
- Recommended: Enable host-level disk encryption (LUKS, BitLocker, FileVault)

**Enabling PostgreSQL encryption (if supported):**

```yaml
# docker-compose.override.yml
services:
  postgresql:
    environment:
      - POSTGRES_INITDB_ARGS=--data-checksums
```

**Neo4j:**
- Graph data in Docker volume `neo4j-data`
- Same encryption considerations as PostgreSQL

**Report Files:**
- Stored in `./reports/` directory
- Contains raw JSON/HTML/CSV scan output
- Recommended: Restrict directory permissions

```bash
chmod 700 reports/
chmod 600 reports/**/*
```

### Data in Transit

**Internal Communication:**
- Containers communicate over Docker bridge network
- Traffic is unencrypted within Docker network
- Considered acceptable for single-host deployment

**External API Access:**
- HTTP by default (port 8000)
- TLS termination recommended via nginx

**Enable TLS:**

```nginx
# nginx/ssl.conf
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    location /api/ {
        proxy_pass http://api:8000/;
    }
}
```

### Data Retention

**Default Behavior:**
- Findings persist indefinitely
- Scan history preserved
- No automatic cleanup

**Recommended Retention Policy:**

```bash
# Delete findings older than 90 days
docker compose exec postgresql psql -U auditor -d security_audits -c \
  "DELETE FROM findings WHERE scan_date < NOW() - INTERVAL '90 days'"

# Archive old scans
docker compose exec postgresql pg_dump -U auditor -d security_audits \
  -t scans --where "completed_at < NOW() - INTERVAL '90 days'" > archive.sql
```

---

## API Authentication

### Authentication Methods

**1. API Key Authentication (Recommended)**

```bash
# Set API key in environment
API_KEY=your-secure-api-key

# Include in requests
curl -H "X-API-Key: your-secure-api-key" http://localhost:8000/api/findings
```

**Implementation Details:**
- Timing-safe string comparison prevents timing attacks
- Key transmitted via `X-API-Key` header
- Failed authentication logged with request ID

**2. No Authentication (Development Only)**

```bash
# Leave API_KEY empty or unset
API_KEY=
```

### Unauthenticated Endpoints

These endpoints bypass authentication for operational purposes:

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `/api/health` | Load balancer checks | Low (no data exposed) |
| `/api/health/live` | Kubernetes liveness | Low |
| `/api/health/ready` | Kubernetes readiness | Low |
| `/api/health/detailed` | Service diagnostics | Low-Medium (versions exposed) |
| `/api/docs` | Swagger UI | Low (schema only) |
| `/api/redoc` | ReDoc UI | Low |
| `/api/openapi.json` | OpenAPI schema | Low |

### Rate Limiting

**Default Configuration:**
- 100 requests per minute per client
- 20 requests burst limit (per second)
- Client identified by API key or IP address

**Customize Rate Limits:**

```bash
# In .env
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=100
RATE_LIMIT_BURST=20
```

**Rate Limit Headers:**

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704067200
Retry-After: 60  (when limited)
```

### CORS Configuration

**Default:**

```bash
API_CORS_ORIGINS=http://localhost:8080,http://localhost:3000
```

**Production:**

```bash
# Restrict to your domain only
API_CORS_ORIGINS=https://security.yourdomain.com
```

### Request Validation

**Input Validation:**
- Pydantic models validate all request bodies
- Type coercion and constraint enforcement
- Invalid requests return 400 with sanitized error

**SQL Injection Prevention:**
- SQLAlchemy ORM with parameterized queries
- No raw SQL with user input
- Table name whitelists for dynamic queries

**Path Traversal Prevention:**
- File paths validated against allowed directories
- No user-controlled paths to filesystem

---

## Credential Handling

### Cloud Provider Credentials

#### Storage Location

```
credentials/
├── aws/
│   ├── credentials     # AWS access keys
│   └── config          # AWS profiles, regions
├── azure/
│   └── credentials.json  # Service principal
└── gcp/
    └── credentials.json  # Service account key
```

**Security Controls:**
- Directory is gitignored
- Mounted read-only into containers
- File permissions should be restricted

```bash
chmod 700 credentials/
chmod 600 credentials/**/*
```

#### AWS Credential Types

**1. Static Access Keys (Development)**

```ini
# credentials/aws/credentials
[nubicustos-audit]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

Security: Moderate risk, requires rotation

**2. IAM Role Assumption (Production)**

```ini
# credentials/aws/config
[profile nubicustos-audit]
role_arn = arn:aws:iam::TARGET:role/NubicustosAuditRole
source_profile = hub-account
```

Security: Improved, short-lived credentials

**3. IMDS/Instance Roles (Cloud Native)**

```yaml
# On EC2 or ECS with instance/task role
# No credentials file needed
# Credentials auto-refreshed
```

Security: Best option for cloud deployments

#### Credential Exposure Prevention

**Environment Variables:**
- Credentials passed via environment variables to containers
- Never logged or exposed in API responses
- Health endpoints exclude credential status

**Container Isolation:**
- Each scan container gets only required credentials
- Credentials mounted read-only
- Container removed after scan completes

**Error Message Sanitization:**

```python
# API returns safe error messages
# "AWS authentication failed" not "Invalid key: AKIA..."
```

### Database Credentials

**PostgreSQL:**

```bash
# In .env (not committed)
POSTGRES_PASSWORD=secure-random-password

# Generated at deployment
POSTGRES_PASSWORD=$(openssl rand -base64 32)
```

**Neo4j:**

```bash
NEO4J_PASSWORD=secure-random-password
```

**Security Controls:**
- Passwords only in `.env` file (gitignored)
- Container-to-container communication via Docker network
- External port binding optional (can be disabled)

### API Key Management

**Generation:**

```bash
# Generate cryptographically random key
API_KEY=$(openssl rand -hex 32)
```

**Rotation:**

```bash
# Generate new key
NEW_API_KEY=$(openssl rand -hex 32)

# Update .env
sed -i "s/API_KEY=.*/API_KEY=${NEW_API_KEY}/" .env

# Restart API
docker compose restart api

# Update MCP clients with new key
```

---

## Log Sanitization

### What Gets Logged

**Request Logging:**

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "request_id": "abc123",
  "method": "POST",
  "path": "/api/scans",
  "status_code": 201,
  "duration_ms": 125.5,
  "client_ip": "192.168.1.100"
}
```

**What is NOT logged:**
- API keys (only prefix logged for rate limiting)
- Request/response bodies
- AWS credentials
- Database passwords
- Finding details (only counts)

### Log Sanitization Rules

**API Key Masking:**

```python
# Logged as: "key:abc12345" (first 8 chars only)
client_id = f"key:{api_key[:8]}"
```

**Path Parameter Sanitization:**

```python
# Resource IDs truncated in logs
# /api/scans/abc123-def456-... -> /api/scans/{scan_id}
```

**Error Message Sanitization:**

```python
# Internal errors get generic messages
# "psycopg2.OperationalError: ..." -> "Database connection failed"
# "FileNotFoundError: /path/..." -> "File not found"
```

### Log Storage

**Default Location:**

```bash
# Container stdout/stderr -> Docker logs
docker compose logs api

# Optional: Write to files
logging:
  driver: json-file
  options:
    max-size: "100m"
    max-file: "5"
```

**Log Retention:**

```bash
# Docker log rotation
# In /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  }
}
```

### Audit Trail

**What is Tracked:**
- Scan initiations (who, when, what profile)
- Finding status changes
- Export requests
- Authentication failures

**Access Audit Query:**

```bash
# Check authentication failures
docker compose logs api | grep "Authentication failed"

# Check scan history
curl -s http://localhost:8000/api/scans | jq '.scans[] | {
  id: .scan_id,
  started: .started_at,
  profile: .scan_type
}'
```

### Compliance Considerations

**PCI-DSS Logging Requirements:**
- Log access to cardholder data environments
- Retain logs for 1 year
- Implement log integrity monitoring

**SOC 2 Logging Requirements:**
- Log system events and access
- Monitor for security events
- Maintain audit trails

**Implementation:**

```bash
# Forward logs to SIEM
docker compose logs api | nc siem.internal 514

# Or use logging driver
services:
  api:
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://siem.internal:514"
```

---

## Security Hardening Checklist

### Pre-Deployment

- [ ] Change all default passwords
- [ ] Generate strong API key
- [ ] Configure TLS termination
- [ ] Restrict CORS origins
- [ ] Review container resource limits
- [ ] Set appropriate file permissions

### Container Security

- [ ] Images pinned to specific versions
- [ ] `no-new-privileges` enabled (where compatible)
- [ ] Capabilities dropped (`cap_drop: ALL`)
- [ ] Read-only filesystem (where possible)
- [ ] Non-root user (where possible)

### Network Security

- [ ] Restrict database ports to internal only
- [ ] Configure firewall rules
- [ ] Enable rate limiting
- [ ] Disable unnecessary endpoints

### Credential Security

- [ ] Use IAM roles instead of access keys
- [ ] Implement credential rotation schedule
- [ ] Monitor for credential exposure
- [ ] Audit credential access

### Monitoring

- [ ] Enable detailed health checks
- [ ] Configure log aggregation
- [ ] Set up alerting for auth failures
- [ ] Monitor container resource usage

---

## Incident Response

### Credential Compromise

**If cloud credentials are exposed:**

1. Immediately rotate affected credentials
2. Review CloudTrail/activity logs for unauthorized access
3. Check for new resources or IAM changes
4. Update credentials in Nubicustos
5. Run fresh security scan

```bash
# Rotate AWS credentials
aws iam create-access-key --user-name nubicustos-audit
aws iam delete-access-key --user-name nubicustos-audit --access-key-id OLD_KEY

# Update credentials file
vim credentials/aws/credentials

# Restart affected services
docker compose restart api
```

### API Key Compromise

**If API key is exposed:**

1. Generate new API key immediately
2. Update all clients
3. Review API logs for unauthorized access
4. Check for suspicious finding exports

```bash
# Generate new key
NEW_KEY=$(openssl rand -hex 32)
sed -i "s/API_KEY=.*/API_KEY=${NEW_KEY}/" .env
docker compose restart api

# Review access logs
docker compose logs api | grep -E "401|403|exports"
```

### Data Breach

**If findings data is exposed:**

1. Assess scope of exposure
2. Notify affected stakeholders
3. Prioritize remediation of exposed vulnerabilities
4. Review and rotate any exposed credentials
5. Conduct post-incident review

---

## Security Contacts

For security issues with Nubicustos:
- Create a private security advisory on GitHub
- Do not disclose vulnerabilities publicly before fix is available
