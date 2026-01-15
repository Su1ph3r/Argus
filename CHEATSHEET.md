# Nubicustos - Command Cheatsheet

Quick reference for common operations and commands.

## Stack Management

### Starting & Stopping
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Cleanup containers/images/volumes (see Cleanup section below)
./scripts/cleanup.sh

# Restart specific service
docker-compose restart [service-name]

# View running services
docker-compose ps

# View logs
docker-compose logs -f [service-name]

# Follow all logs
docker-compose logs -f
```

### Health Checks
```bash
# Check all container status
docker-compose ps

# Test database connection
docker-compose exec postgresql pg_isready -U auditor

# Test Neo4j connection
curl -u neo4j:password http://localhost:7474/db/data/

# Check Nginx
curl http://localhost:8080/health
```

## Running Audits

### Full Audit
```bash
# Run complete audit across all platforms
./scripts/run-all-audits.sh
```

### Individual Cloud Providers
```bash
# AWS only
docker-compose run --rm prowler aws
docker-compose run --rm scoutsuite-aws
docker-compose run --rm pacu

# CloudSploit (multi-cloud)
docker-compose run --rm cloudsploit
```

### Kubernetes Scans
```bash
# CIS Benchmarks
docker-compose run --rm kube-bench

# Compliance frameworks
docker-compose run --rm kubescape scan

# Container images
docker-compose run --rm trivy image nginx:latest

# Cluster resources
docker-compose run --rm popeye
```

### IaC Scanning
```bash
# Checkov (all frameworks)
docker-compose run --rm checkov -d /code

# Terrascan (Terraform)
docker-compose run --rm terrascan scan -i terraform -d /iac

# tfsec (Terraform specific)
docker-compose run --rm tfsec /src
```

## Database Operations

### Connecting to PostgreSQL
```bash
# Interactive session
docker-compose exec postgresql psql -U auditor -d security_audits

# Run single query
docker-compose exec postgresql psql -U auditor -d security_audits -c "SELECT COUNT(*) FROM findings;"
```

### Common Queries

```sql
-- Count findings by severity
SELECT severity, COUNT(*) as count 
FROM findings 
GROUP BY severity 
ORDER BY count DESC;

-- Recent critical findings
SELECT finding_id, resource_id, title 
FROM findings 
WHERE severity = 'critical' 
AND scan_date > NOW() - INTERVAL '7 days'
ORDER BY scan_date DESC;

-- Findings by cloud provider
SELECT cloud_provider, COUNT(*) as total
FROM findings
WHERE status = 'open'
GROUP BY cloud_provider;

-- Top vulnerable resources
SELECT resource_type, COUNT(*) as findings_count
FROM findings
WHERE status = 'open'
GROUP BY resource_type
ORDER BY findings_count DESC
LIMIT 10;

-- Get remediation guidance for a finding
SELECT finding_id, title, remediation
FROM findings
WHERE finding_id = 'FINDING_ID_HERE';

-- Export findings to CSV
\COPY (SELECT * FROM findings WHERE status='open') TO '/tmp/findings.csv' CSV HEADER
```

### Database Maintenance
```bash
# Vacuum database
docker-compose exec postgresql vacuumdb -U auditor -d security_audits

# Analyze tables
docker-compose exec postgresql psql -U auditor -d security_audits -c "ANALYZE;"

# Database size
docker-compose exec postgresql psql -U auditor -d security_audits -c "
SELECT pg_size_pretty(pg_database_size('security_audits'));"
```

## Neo4j Graph Database

### Connecting
```bash
# Web interface
open http://localhost:7474
# Login: neo4j / your-password
```

### Common Cypher Queries

```cypher
# Count all nodes
MATCH (n) RETURN count(n);

# Find all AWS S3 buckets
MATCH (s:S3Bucket) RETURN s;

# Find public S3 buckets
MATCH (s:S3Bucket {public: true}) RETURN s;

# Find EC2 instances in security groups with open ports
MATCH (i:EC2Instance)-[:MEMBER_OF_SECURITY_GROUP]->(sg:SecurityGroup)
WHERE sg.inbound_rules CONTAINS '0.0.0.0/0'
RETURN i, sg;

# Find relationships between resources
MATCH (a)-[r]->(b)
RETURN type(r), count(*) as count
ORDER BY count DESC;

# Clear all data (careful!)
MATCH (n) DETACH DELETE n;
```

## Exporting Results

### Export Findings
```bash
# Export all findings with remediation
./scripts/export-findings.sh

# Exports created in: reports/exports/
```

### Manual Exports
```bash
# All findings to CSV
docker-compose exec postgresql psql -U auditor -d security_audits -c "
\COPY (SELECT * FROM findings) TO STDOUT CSV HEADER" > all_findings.csv

# Critical/High only
docker-compose exec postgresql psql -U auditor -d security_audits -c "
\COPY (SELECT finding_id, resource_id, severity, title, remediation FROM findings 
WHERE severity IN ('critical', 'high') AND status = 'open') 
TO STDOUT CSV HEADER" > critical_findings.csv

# Compliance summary
docker-compose exec postgresql psql -U auditor -d security_audits -c "
\COPY (SELECT * FROM compliance_coverage) TO STDOUT CSV HEADER" > compliance.csv
```

### Backup Data
```bash
# PostgreSQL database
docker-compose exec postgresql pg_dump -U auditor security_audits > backup_$(date +%Y%m%d).sql

# Neo4j graph
docker-compose exec neo4j neo4j-admin dump --to=/data/backup_$(date +%Y%m%d).dump

# All reports
tar -czf reports_backup_$(date +%Y%m%d).tar.gz reports/
```

## Viewing Reports

### Web Interface
```bash
# Open main page
open http://localhost:8080

# Specific tool reports
open http://localhost:8080/reports/prowler
open http://localhost:8080/reports/kubescape
open http://localhost:8080/reports/checkov
```

### Command Line
```bash
# List all reports
ls -lh reports/*/

# View JSON report with jq
jq '.' reports/prowler/prowler-output-*.json | less

# Count findings in JSON
jq '. | length' reports/kubescape/kubescape-results.json

# Extract specific fields
jq '.[] | {severity, title, resource_id}' reports/prowler/*.json
```

## Troubleshooting

### Container Issues
```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs [service-name]

# Restart container
docker-compose restart [service-name]

# Rebuild and restart
docker-compose up -d --force-recreate --build [service-name]

# Enter container shell
docker-compose exec [service-name] /bin/bash
```

### Cleanup Utility
```bash
# Interactive cleanup menu
./scripts/cleanup.sh

# Containers only (safe)
./scripts/cleanup.sh --containers

# Remove locally built images (api, frontend)
./scripts/cleanup.sh --images-local

# Remove all images (requires re-download)
./scripts/cleanup.sh --images

# Remove volumes (WARNING: deletes databases!)
./scripts/cleanup.sh --volumes

# Complete cleanup (all above + prune)
./scripts/cleanup.sh --all

# Preview actions without executing
./scripts/cleanup.sh --dry-run --all

# Skip confirmation prompts
./scripts/cleanup.sh --all --force
```

### Disk Space
```bash
# Check Docker disk usage
docker system df

# Clean unused images/containers (manual)
docker system prune -a

# Remove old volumes (manual)
docker volume prune

# Clean old reports (older than 30 days)
find reports/ -type f -mtime +30 -delete
```

### Database Issues
```bash
# Reset database
docker-compose down -v postgresql
docker-compose up -d postgresql

# Check connections
docker-compose exec postgresql psql -U auditor -d security_audits -c "
SELECT count(*) FROM pg_stat_activity WHERE datname='security_audits';"

# Kill idle connections
docker-compose exec postgresql psql -U auditor -d security_audits -c "
SELECT pg_terminate_backend(pid) FROM pg_stat_activity 
WHERE datname='security_audits' AND state='idle';"
```

### Network Issues
```bash
# List Docker networks
docker network ls

# Inspect security network
docker network inspect cloud-security-audit-stack_security-net

# Recreate network
docker-compose down
docker-compose up -d
```

## Performance Tuning

### Resource Limits
```bash
# Edit docker-compose.yml to add resource limits
services:
  prowler:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
```

### Parallel Execution
```bash
# Run multiple tools simultaneously
docker-compose run -d prowler aws &
docker-compose run -d kubescape scan &
docker-compose run -d checkov &
wait
```

### Database Performance
```sql
-- Vacuum and analyze
VACUUM ANALYZE;

-- Reindex tables
REINDEX DATABASE security_audits;

-- Check slow queries
SELECT query, mean_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

## Security Hardening

### Update Passwords
```bash
# Edit .env file
nano .env

# Update passwords:
# POSTGRES_PASSWORD=new_strong_password
# NEO4J_PASSWORD=new_strong_password

# Restart services
docker-compose down
docker-compose up -d
```

### Restrict Access
```bash
# Bind Nginx to localhost only
# Edit docker-compose.yml:
nginx:
  ports:
    - "127.0.0.1:8080:80"

# Or use firewall rules
sudo ufw allow from 10.0.0.0/8 to any port 8080
```

### Rotate Credentials
```bash
# AWS credentials
aws configure --profile security-audit
cp ~/.aws/credentials credentials/aws/

# Azure
az login
az account set --subscription "subscription-id"

# GCP
gcloud auth application-default login
```

## Maintenance Tasks

### Daily
```bash
# Check service health
docker-compose ps
```

### Weekly
```bash
# Clean old logs
find logs/ -name "*.log" -mtime +7 -delete

# Update tool images
docker-compose pull
docker-compose up -d
```

### Monthly
```bash
# Clean old reports
find reports/ -type f -mtime +90 -delete

# Vacuum database
docker-compose exec postgresql vacuumdb -U auditor -d security_audits

# Backup critical data
./scripts/backup-all.sh  # (create this if needed)
```

## Quick Fixes

### "Port already in use"
```bash
# Change ports in .env
POSTGRES_PORT=5433
NEO4J_HTTP_PORT=7475
NGINX_PORT=8081
```

### "Permission denied" on scripts
```bash
chmod +x scripts/*.sh
```

### "No space left on device"
```bash
docker system prune -a --volumes
find reports/ -type f -mtime +30 -delete
```

### "Connection refused" to database
```bash
docker-compose restart postgresql
# Wait 10 seconds
docker-compose exec postgresql pg_isready
```

### Can't connect to Kubernetes
```bash
# Test kubeconfig
kubectl --kubeconfig=kubeconfigs/config get nodes

# Fix permissions
chmod 600 kubeconfigs/config
```

## Environment Variables

```bash
# View current configuration
docker-compose config

# Override for single run
ENABLE_PACU=false docker-compose run prowler aws

# Edit environment
nano .env
docker-compose down && docker-compose up -d
```

## Getting Help

```bash
# Tool-specific help
docker-compose run prowler --help
docker-compose run kubescape scan --help

# Container logs
docker-compose logs --tail=100 [service-name]

# System information
docker info
docker-compose version
```
