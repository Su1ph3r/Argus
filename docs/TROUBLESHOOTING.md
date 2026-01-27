# Nubicustos Troubleshooting Guide

This guide provides solutions for common issues encountered when running Nubicustos.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Credential Issues](#credential-issues)
- [Scan Failures](#scan-failures)
- [Database Issues](#database-issues)
- [Docker Issues](#docker-issues)
- [Performance Issues](#performance-issues)

---

## Quick Diagnostics

### Health Check Commands

Run these commands to quickly assess system health:

```bash
# Check API health
curl -s http://localhost:8000/api/health | jq .

# Detailed health with all services
curl -s http://localhost:8000/api/health/detailed | jq .

# Check specific containers
docker compose ps

# View recent API logs
docker compose logs api --tail 50

# Check database connectivity
docker compose exec postgresql pg_isready -U auditor -d security_audits
```

### Service Status Matrix

| Service | Health Check | Expected Response |
|---------|--------------|-------------------|
| API | `curl http://localhost:8000/api/health` | `{"status": "healthy"}` |
| PostgreSQL | `docker compose exec postgresql pg_isready` | `/var/run/postgresql:5432 - accepting connections` |
| Neo4j | `curl http://localhost:7474` | HTTP 200 (browser interface) |
| Nginx | `curl http://localhost:8080` | HTTP 200 (frontend) |

### Container Health Overview

```bash
# Quick status of all containers
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# Check for unhealthy containers
docker ps --filter "health=unhealthy" --format "{{.Names}}: {{.Status}}"
```

---

## Credential Issues

### AWS Credential Problems

#### Symptoms
- Scans fail immediately with "credentials not found"
- Prowler exits with "NoCredentialProviders" error
- ScoutSuite reports "Unable to locate credentials"

#### Diagnosis

```bash
# Check if credentials directory exists and has files
ls -la credentials/aws/

# Verify credentials file format
cat credentials/aws/credentials

# Test AWS credentials from container
docker compose exec api sh -c "cat /app/credentials/aws/credentials"
```

#### Solutions

**1. Missing credentials file:**

```bash
# Create credentials directory
mkdir -p credentials/aws

# Copy from local AWS config
cp ~/.aws/credentials credentials/aws/
cp ~/.aws/config credentials/aws/
```

**2. Wrong profile name:**

The default profile is `nubicustos-audit`. Either create this profile or specify a different one:

```bash
# Option A: Create the expected profile
cat >> credentials/aws/credentials << 'EOF'
[nubicustos-audit]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
EOF

# Option B: Use existing profile via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "aws_profile": "your-profile-name"}'
```

**3. IMDS credentials (EC2/ECS):**

When running on EC2 or ECS, credentials should be automatic via instance/task roles. If not working:

```bash
# Check if IMDS is accessible from container
docker compose exec api curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Verify IAM role has SecurityAudit policy attached
```

**4. Permission denied errors:**

```bash
# Fix file permissions
chmod 600 credentials/aws/credentials
chmod 644 credentials/aws/config
```

### Azure Credential Problems

#### Symptoms
- Azure scans fail with "authentication failed"
- Prowler Azure reports "ClientSecretCredential authentication failed"

#### Solutions

**1. Create service principal credentials:**

```bash
# Create credentials file
cat > credentials/azure/credentials.json << 'EOF'
{
  "AZURE_CLIENT_ID": "your-client-id",
  "AZURE_CLIENT_SECRET": "your-client-secret",
  "AZURE_TENANT_ID": "your-tenant-id",
  "AZURE_SUBSCRIPTION_ID": "your-subscription-id"
}
EOF
```

**2. Verify service principal permissions:**

The service principal needs at minimum `Reader` role on subscriptions to audit.

```bash
# Test Azure login with service principal
az login --service-principal \
  -u "your-client-id" \
  -p "your-client-secret" \
  --tenant "your-tenant-id"

# Verify access
az account show
```

### GCP Credential Problems

#### Solutions

```bash
# Place service account key
cp /path/to/service-account.json credentials/gcp/credentials.json

# Set correct permissions
chmod 600 credentials/gcp/credentials.json
```

---

## Scan Failures

### Scan Stuck in "Running" Status

#### Symptoms
- Scan status shows "running" indefinitely
- No new findings appearing
- Container may have exited

#### Diagnosis

```bash
# Check if scan container is still running
docker ps | grep -E "prowler|scoutsuite|cloudfox"

# Get scan details
curl -s "http://localhost:8000/api/scans" | jq '.scans[] | select(.status=="running")'

# Check scan errors
SCAN_ID="your-scan-id"
curl -s "http://localhost:8000/api/scans/${SCAN_ID}/errors" | jq .
```

#### Solutions

**1. Cancel stuck scan:**

```bash
curl -X DELETE "http://localhost:8000/api/scans/${SCAN_ID}"
```

**2. Force cleanup via database:**

```bash
docker compose exec postgresql psql -U auditor -d security_audits -c \
  "UPDATE scans SET status = 'failed', completed_at = NOW() WHERE status = 'running'"
```

**3. Restart API (triggers orphan recovery):**

```bash
docker compose restart api
# Orphan recovery runs automatically on startup
```

### Zero Findings After Scan

#### Symptoms
- Scan completes successfully
- `total_findings: 0` in scan results
- Report files exist but are empty

#### Diagnosis

```bash
# Check if reports were generated
ls -la reports/prowler/
ls -la reports/scoutsuite/

# Check report content
head -20 reports/prowler/*.json

# Verify database has findings
docker compose exec postgresql psql -U auditor -d security_audits -c \
  "SELECT COUNT(*) FROM findings WHERE scan_id = 'your-scan-id'::uuid"
```

#### Solutions

**1. Report processing failed - process manually:**

```bash
# Run report processor directly
docker compose exec api python /app/report-processor/process_reports.py \
  --reports-dir /reports \
  --scan-id your-scan-id
```

**2. Missing database columns (Linux issue):**

```bash
# API should auto-migrate, but verify columns exist
docker compose exec postgresql psql -U auditor -d security_audits -c \
  "SELECT column_name FROM information_schema.columns WHERE table_name='findings'" | grep -E "canonical_id|tool_sources"

# If columns missing, restart API to trigger migrations
docker compose restart api
```

**3. AWS region/account issues:**

```bash
# Verify correct account is being scanned
docker compose logs prowler-scan-* 2>/dev/null | head -20

# Check AWS credentials are for correct account
aws sts get-caller-identity --profile nubicustos-audit
```

### Container Build Failures

#### Symptoms
- Scan fails with "Image not found"
- Local build tools (cloudfox, enumerate-iam) unavailable

#### Solutions

```bash
# Build all local images manually
docker compose build cloudfox
docker compose build enumerate-iam

# Or rebuild via scripts
./scripts/build-local-images.sh

# Check image exists
docker images | grep -E "cloudfox|enumerate-iam"
```

---

## Database Issues

### Connection Failures

#### Symptoms
- API returns 500 errors
- Health check shows database unhealthy
- "connection refused" in logs

#### Diagnosis

```bash
# Check PostgreSQL container
docker compose ps postgresql
docker compose logs postgresql --tail 20

# Test connection
docker compose exec postgresql pg_isready -U auditor -d security_audits

# Check disk space (PostgreSQL needs space)
docker compose exec postgresql df -h /var/lib/postgresql/data
```

#### Solutions

**1. Container not running:**

```bash
docker compose up -d postgresql
# Wait for healthy status
docker compose ps postgresql
```

**2. Password mismatch:**

Check `.env` file matches what PostgreSQL was initialized with. If password changed, you may need to reset:

```bash
# WARNING: This deletes all data
docker compose down postgresql
docker volume rm nubicustos_postgres-data
docker compose up -d postgresql
```

**3. Port conflict:**

```bash
# Check if port 5432 is in use
lsof -i :5432

# Use different port in .env
POSTGRES_PORT=5433
```

### Migration Failures

#### Symptoms
- API logs show "Migration failed"
- Missing columns in tables
- Queries fail with "column does not exist"

#### Diagnosis

```bash
# Check current columns
docker compose exec postgresql psql -U auditor -d security_audits -c \
  "\d findings"

# View migration logs
docker compose logs api | grep -i migration
```

#### Solutions

**Run migrations manually:**

```bash
# Connect to database
docker compose exec postgresql psql -U auditor -d security_audits

# Add missing columns (example)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS canonical_id VARCHAR(256);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tool_sources JSONB DEFAULT '[]';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS affected_resources JSONB DEFAULT '[]';
```

### Database Corruption / Recovery

```bash
# Create backup before any recovery
docker compose exec postgresql pg_dump -U auditor -Fc security_audits > backup.dump

# Verify backup
docker compose exec -T postgresql pg_restore --list backup.dump

# Restore if needed
docker compose exec -T postgresql pg_restore -U auditor -d security_audits --clean < backup.dump
```

---

## Docker Issues

### Docker Socket Permissions (Linux)

#### Symptoms
- Scans fail with "permission denied" accessing Docker socket
- "Got permission denied while trying to connect to the Docker daemon"

#### Solutions

**1. Run the Linux setup script:**

```bash
./scripts/setup-linux-permissions.sh
```

**2. Manual fix:**

```bash
# Get Docker group ID
DOCKER_GID=$(getent group docker | cut -d: -f3)

# Add to .env
echo "DOCKER_GID=${DOCKER_GID}" >> .env

# Restart stack
docker compose down
docker compose up -d
```

**3. Alternative - add user to docker group:**

```bash
sudo usermod -aG docker $USER
# Log out and back in, then restart docker compose
```

### Disk Space Issues

#### Symptoms
- Containers fail to start
- "no space left on device" errors
- Database writes fail

#### Diagnosis

```bash
# Check host disk space
df -h

# Check Docker disk usage
docker system df

# Find large containers/images
docker system df -v
```

#### Solutions

```bash
# Clean unused Docker resources
docker system prune -f

# Clean old reports (keep last 7 days)
find reports/ -type f -mtime +7 -delete

# Clean old scan archives
find /tmp/nubicustos-archives -type f -mtime +1 -delete 2>/dev/null

# Vacuum PostgreSQL
docker compose exec postgresql vacuumdb -U auditor -d security_audits --analyze
```

### Container Resource Limits

#### Symptoms
- Containers killed with OOMKilled
- Scans timeout unexpectedly
- Slow container performance

#### Solutions

Add resource limits to `docker-compose.override.yml`:

```yaml
services:
  prowler:
    deploy:
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 1G

  api:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'
```

---

## Performance Issues

### Slow Scans

#### Symptoms
- Scans take much longer than expected
- High CPU/memory usage during scans
- API becomes unresponsive

#### Diagnosis

```bash
# Check container resource usage
docker stats --no-stream

# Check API response time
time curl -s http://localhost:8000/api/health > /dev/null

# Check database query performance
docker compose exec postgresql psql -U auditor -d security_audits -c \
  "SELECT query, calls, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10"
```

#### Solutions

**1. Limit scan scope:**

```bash
# Use quick profile instead of comprehensive
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "severity_filter": "critical,high"}'
```

**2. Increase container resources:**

See [Container Resource Limits](#container-resource-limits) above.

**3. Database optimization:**

```bash
# Run vacuum and analyze
docker compose exec postgresql vacuumdb -U auditor -d security_audits --analyze --full

# Create additional indexes if needed
docker compose exec postgresql psql -U auditor -d security_audits -c \
  "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_severity ON findings(severity)"
```

### Memory Leaks

#### Symptoms
- Container memory usage grows over time
- Eventually hits limits and restarts

#### Solutions

```bash
# Set restart policy
# In docker-compose.override.yml:
services:
  api:
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2G

# Monitor memory over time
docker stats api --format "{{.MemUsage}}"
```

### API Response Timeouts

#### Symptoms
- API requests timeout
- "504 Gateway Timeout" from nginx
- Large finding queries fail

#### Solutions

**1. Increase timeout settings:**

```bash
# In .env
SHUTDOWN_TIMEOUT=60
```

**2. Use pagination for large queries:**

```bash
# Instead of fetching all findings
curl "http://localhost:8000/api/findings?page=1&page_size=100"
```

**3. Reduce finding result size:**

```bash
# Filter by severity or status
curl "http://localhost:8000/api/findings?severity=critical,high&status=open"
```

---

## Getting More Help

### Enable Debug Logging

```bash
# In .env
LOG_LEVEL=DEBUG

# Restart API
docker compose restart api

# View debug logs
docker compose logs api -f
```

### Collect Diagnostic Information

```bash
# Create diagnostic bundle
mkdir -p /tmp/nubicustos-diag
docker compose logs > /tmp/nubicustos-diag/all-logs.txt
docker compose ps > /tmp/nubicustos-diag/container-status.txt
docker system df > /tmp/nubicustos-diag/docker-disk.txt
curl -s http://localhost:8000/api/health/detailed > /tmp/nubicustos-diag/health.json
tar -czvf nubicustos-diagnostic.tar.gz /tmp/nubicustos-diag/
```

### Container Shell Access

```bash
# API container
docker compose exec api /bin/sh

# PostgreSQL
docker compose exec postgresql psql -U auditor -d security_audits

# Check tool container during scan
docker exec -it prowler-scan-abc123 /bin/sh
```
