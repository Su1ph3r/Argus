# Nubicustos Performance Guide

This guide provides recommendations for optimizing Nubicustos performance, especially when scanning large cloud environments.

## Table of Contents

- [Large Account Guidance](#large-account-guidance)
- [Database Tuning](#database-tuning)
- [Container Resource Allocation](#container-resource-allocation)
- [Scan Parallelization](#scan-parallelization)

---

## Large Account Guidance

### Understanding Scale Challenges

Large AWS accounts (10,000+ resources) present specific challenges:

| Resource Count | Expected Scan Time | Memory Requirements | Storage Impact |
|----------------|-------------------|---------------------|----------------|
| < 1,000 | 5-15 min | 2 GB | < 100 MB |
| 1,000 - 5,000 | 15-30 min | 4 GB | 100-500 MB |
| 5,000 - 10,000 | 30-60 min | 8 GB | 500 MB - 1 GB |
| 10,000 - 50,000 | 1-3 hours | 16 GB | 1-5 GB |
| 50,000+ | 3+ hours | 32 GB+ | 5+ GB |

### Pre-Scan Assessment

Before running comprehensive scans on large accounts:

```bash
# Count resources via AWS CLI
aws resourcegroupstaggingapi get-resources --query "length(ResourceTagMappingList)" --profile your-profile

# Or use Prowler's quick count
docker compose run --rm prowler aws --list-checks-json | wc -l
```

### Recommended Approach for Large Accounts

**1. Start with targeted scans:**

```bash
# Scan only critical services first
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "quick",
    "severity_filter": "critical,high"
  }'
```

**2. Scan by region:**

```bash
# Create region-specific scans
for region in us-east-1 us-west-2 eu-west-1; do
  curl -X POST http://localhost:8000/api/scans \
    -H "Content-Type: application/json" \
    -d "{\"profile\": \"quick\", \"target\": \"$region\"}"
done
```

**3. Scan by service:**

```bash
# Focus on specific AWS services
# Prowler supports service filtering
docker compose run --rm prowler aws \
  --services s3 iam ec2 rds \
  --profile nubicustos-audit
```

### Multi-Account Strategies

For organizations with many AWS accounts:

**Hub-and-Spoke Model:**

```bash
# Set up cross-account role assumption
# In spoke accounts, create role: NubicustosAuditRole
# In hub account, assume roles for scanning

# Configure profiles for each account
cat > credentials/aws/config << 'EOF'
[profile account-production]
role_arn = arn:aws:iam::111111111111:role/NubicustosAuditRole
source_profile = hub-account

[profile account-staging]
role_arn = arn:aws:iam::222222222222:role/NubicustosAuditRole
source_profile = hub-account

[profile account-development]
role_arn = arn:aws:iam::333333333333:role/NubicustosAuditRole
source_profile = hub-account
EOF
```

**Parallel Account Scanning:**

```bash
# Scan multiple accounts in parallel (with resource limits)
for profile in account-production account-staging account-development; do
  curl -X POST http://localhost:8000/api/scans \
    -H "Content-Type: application/json" \
    -d "{\"profile\": \"quick\", \"aws_profile\": \"$profile\"}" &
done
wait
```

### Memory Management for Large Scans

**1. Increase container memory:**

```yaml
# docker-compose.override.yml
services:
  prowler:
    deploy:
      resources:
        limits:
          memory: 8G
        reservations:
          memory: 4G
```

**2. Enable swap (if needed):**

```bash
# On the Docker host
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

**3. Monitor memory during scans:**

```bash
# Real-time memory monitoring
docker stats prowler-scan-* --format "{{.Name}}: {{.MemUsage}}"
```

---

## Database Tuning

### PostgreSQL Configuration

For large finding datasets, tune PostgreSQL for better performance.

**1. Connection settings:**

```yaml
# docker-compose.override.yml
services:
  postgresql:
    command:
      - "postgres"
      - "-c"
      - "max_connections=200"
      - "-c"
      - "shared_buffers=2GB"
      - "-c"
      - "effective_cache_size=6GB"
      - "-c"
      - "work_mem=256MB"
      - "-c"
      - "maintenance_work_mem=512MB"
```

**2. Performance tuning:**

```sql
-- Connect to database
docker compose exec postgresql psql -U auditor -d security_audits

-- Tune autovacuum for large tables
ALTER TABLE findings SET (
  autovacuum_vacuum_scale_factor = 0.05,
  autovacuum_analyze_scale_factor = 0.02
);

-- Set parallel query workers
SET max_parallel_workers_per_gather = 4;
```

### Vacuum and Maintenance

Regular maintenance is essential for large databases.

**Daily maintenance script:**

```bash
#!/bin/bash
# scripts/db-maintenance.sh

# Run vacuum analyze on key tables
docker compose exec postgresql vacuumdb \
  -U auditor \
  -d security_audits \
  --analyze \
  --verbose

# Check table bloat
docker compose exec postgresql psql -U auditor -d security_audits -c "
SELECT
  schemaname || '.' || tablename AS table,
  pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS size,
  n_dead_tup AS dead_tuples
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC
LIMIT 10;
"
```

**Weekly full vacuum:**

```bash
# Run during maintenance window (locks tables briefly)
docker compose exec postgresql vacuumdb \
  -U auditor \
  -d security_audits \
  --full \
  --analyze
```

### Index Optimization

Create indexes for common query patterns:

```sql
-- Connect to database
docker compose exec postgresql psql -U auditor -d security_audits

-- Index for severity filtering (most common)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_severity
ON findings(severity);

-- Index for status filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_status
ON findings(status);

-- Composite index for common query pattern
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_status_severity
ON findings(status, severity);

-- Index for resource type queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_resource_type
ON findings(resource_type);

-- Index for cloud provider filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_cloud_provider
ON findings(cloud_provider);

-- Index for scan date range queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_scan_date
ON findings(scan_date DESC);

-- Index for finding deduplication
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_canonical_id
ON findings(canonical_id) WHERE canonical_id IS NOT NULL;

-- Full-text search index for title/description
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_search
ON findings USING gin(to_tsvector('english', title || ' ' || COALESCE(description, '')));
```

**Check index usage:**

```sql
SELECT
  indexrelname AS index,
  idx_scan AS times_used,
  pg_size_pretty(pg_relation_size(indexrelid)) AS size
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;
```

### Query Performance Analysis

**Enable query statistics:**

```sql
-- Enable pg_stat_statements extension
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- View slowest queries
SELECT
  query,
  calls,
  round(mean_exec_time::numeric, 2) AS avg_ms,
  round(total_exec_time::numeric, 2) AS total_ms
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

**Explain slow queries:**

```sql
EXPLAIN ANALYZE
SELECT * FROM findings
WHERE severity = 'critical'
  AND status = 'open'
ORDER BY risk_score DESC
LIMIT 100;
```

---

## Container Resource Allocation

### Recommended Resource Limits

Base your resource allocation on account size and available host resources.

**Small environment (< 5,000 resources):**

```yaml
# docker-compose.override.yml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M

  postgresql:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '0.5'
          memory: 1G

  prowler:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 1G
```

**Large environment (10,000+ resources):**

```yaml
# docker-compose.override.yml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 1G

  postgresql:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G

  prowler:
    deploy:
      resources:
        limits:
          cpus: '8'
          memory: 16G
        reservations:
          cpus: '4'
          memory: 8G

  neo4j:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '1'
          memory: 4G
```

### CPU Allocation Strategy

| Component | CPU Priority | Notes |
|-----------|--------------|-------|
| Scanning tools | Highest | CPU-bound during API calls |
| PostgreSQL | Medium-High | Query processing needs |
| API | Medium | Mostly I/O bound |
| Neo4j | Medium | Graph queries can be CPU-intensive |
| Nginx | Low | Minimal processing |

### Memory Allocation Strategy

| Component | Memory Priority | Notes |
|-----------|-----------------|-------|
| PostgreSQL | Highest | Caches improve query speed |
| Scanning tools | High | Large reports need memory |
| Neo4j | Medium-High | Graph caching improves performance |
| API | Medium | Request handling, JSON processing |
| Nginx | Low | Mostly static content |

### Monitoring Resource Usage

**Real-time monitoring:**

```bash
# Monitor all containers
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Monitor specific scan container
docker stats prowler-scan-abc123 --no-stream
```

**Historical analysis:**

```bash
# Export stats to file for analysis
docker stats --no-stream --format \
  "{{.Name}},{{.CPUPerc}},{{.MemUsage}}" >> /tmp/docker-stats.csv

# Analyze peak usage
sort -t',' -k3 -rh /tmp/docker-stats.csv | head -10
```

---

## Scan Parallelization

### Understanding Scan Profiles

| Profile | Tools | Parallelization | Duration |
|---------|-------|-----------------|----------|
| quick | Prowler only | None (single tool) | 5-10 min |
| comprehensive | 9 tools | Tools run sequentially | 30-50 min |
| compliance-only | 2 tools | Sequential | 15-20 min |
| azure-quick | Prowler (Azure) | None | 5-10 min |
| azure-comprehensive | 2 tools | Sequential | 15-25 min |

### Parallel Scan Strategies

**1. Run multiple quick scans:**

```bash
# Parallel quick scans for different accounts
curl -X POST http://localhost:8000/api/scans -d '{"profile":"quick","aws_profile":"prod"}' &
curl -X POST http://localhost:8000/api/scans -d '{"profile":"quick","aws_profile":"staging"}' &
curl -X POST http://localhost:8000/api/scans -d '{"profile":"quick","aws_profile":"dev"}' &
wait
```

**2. Stagger comprehensive scans:**

```bash
# Avoid resource contention by staggering
curl -X POST http://localhost:8000/api/scans -d '{"profile":"comprehensive","aws_profile":"prod"}'
sleep 1800  # Wait 30 minutes
curl -X POST http://localhost:8000/api/scans -d '{"profile":"comprehensive","aws_profile":"staging"}'
```

**3. Service-specific parallelization:**

```bash
# Run different tools in parallel (requires custom orchestration)
# Prowler for compliance
docker compose run -d --name prowler-compliance prowler aws --compliance cis_2.0_aws

# CloudFox for enumeration (different focus)
docker compose run -d --name cloudfox-enum cloudfox aws all-checks

# Wait for both
docker wait prowler-compliance cloudfox-enum
```

### Rate Limiting Considerations

**AWS API Rate Limits:**

Most AWS APIs have per-account rate limits. When running parallel scans:

| API | Typical Limit | Impact |
|-----|--------------|--------|
| IAM | 15 req/sec | Slow down IAM-heavy tools |
| EC2 | 100 req/sec | Usually sufficient |
| S3 | 3500 PUT/GET per prefix | Rarely hit |
| Organizations | 10 req/sec | Limit multi-account enumeration |

**Handling rate limits:**

```bash
# Prowler has built-in retry logic
# For custom scripts, implement exponential backoff

# Check for throttling in logs
docker compose logs prowler 2>&1 | grep -i throttl
```

### IaC Scan Parallelization

IaC scans are inherently parallelizable since they don't call cloud APIs:

```bash
# Parallel IaC scans (different tools)
curl -X POST http://localhost:8000/api/iac/scan \
  -d '{"profile":"iac-quick","path":"/path/to/terraform"}'

curl -X POST http://localhost:8000/api/iac/scan \
  -d '{"profile":"kubernetes-manifests","path":"/path/to/k8s"}'
```

### Optimizing Scan Schedules

**Schedule scans during off-hours:**

```bash
# Use API scheduling (Phase 1 feature)
curl -X POST http://localhost:8000/api/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "nightly-comprehensive",
    "profile": "comprehensive",
    "cron_expression": "0 2 * * *",
    "aws_profile": "production"
  }'
```

**Stagger across the week:**

```bash
# Monday: Production comprehensive
# Tuesday: Staging comprehensive
# Wednesday: Development comprehensive
# Thursday-Sunday: Quick scans only
```

### Performance Benchmarks

Baseline performance on recommended hardware (8 CPU, 32GB RAM):

| Scenario | Resources | Profile | Time |
|----------|-----------|---------|------|
| Small AWS | 500 | quick | 3 min |
| Small AWS | 500 | comprehensive | 18 min |
| Medium AWS | 2,500 | quick | 8 min |
| Medium AWS | 2,500 | comprehensive | 35 min |
| Large AWS | 10,000 | quick | 25 min |
| Large AWS | 10,000 | comprehensive | 90 min |
| IaC Terraform | 50 files | iac-comprehensive | 2 min |
| IaC K8s | 100 manifests | kubernetes-manifests | 3 min |

### Monitoring Scan Performance

```bash
# Check scan duration history
curl -s http://localhost:8000/api/scans | jq '.scans[] | {
  id: .scan_id,
  profile: .scan_type,
  duration_min: (
    ((.completed_at | fromdateiso8601) - (.started_at | fromdateiso8601)) / 60 | floor
  ),
  findings: .total_findings
}'
```

---

## Quick Reference

### Performance Checklist

Before running large scans:

- [ ] Database has adequate disk space (10x expected report size)
- [ ] Container memory limits set appropriately
- [ ] Recent vacuum/analyze run on database
- [ ] Indexes created for common query patterns
- [ ] Rate limiting configured if running parallel scans
- [ ] Monitoring in place (docker stats, API health)

### Emergency Performance Commands

```bash
# Kill stuck scan containers
docker ps | grep "scan-" | awk '{print $1}' | xargs docker kill

# Force garbage collection
docker system prune -f

# Emergency vacuum
docker compose exec postgresql vacuumdb -U auditor -d security_audits --analyze

# Restart API (clears connections, triggers orphan recovery)
docker compose restart api

# Check disk usage
docker system df && df -h
```
