# Quick Installation Guide

## Prerequisites Check

```bash
# Verify Docker
docker --version
# Required: Docker Engine 20.10+

# Verify Docker Compose
docker-compose --version
# Required: Docker Compose 2.0+

# Check available resources
docker info | grep -E 'CPUs|Total Memory'
# Recommended: 4+ CPUs, 16GB+ RAM
```

## 5-Minute Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/cloud-security-audit-stack.git
cd cloud-security-audit-stack
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit passwords (required)
nano .env
# Change: POSTGRES_PASSWORD, NEO4J_PASSWORD
```

### 3. Setup AWS Credentials (Minimum)
```bash
mkdir -p credentials/aws

# Option A: Copy existing AWS credentials
cp ~/.aws/credentials credentials/aws/
cp ~/.aws/config credentials/aws/

# Option B: Create new credentials file
cat > credentials/aws/credentials << EOF
[default]
aws_access_key_id = YOUR_ACCESS_KEY_HERE
aws_secret_access_key = YOUR_SECRET_KEY_HERE
EOF

cat > credentials/aws/config << EOF
[default]
region = us-east-1
output = json
EOF
```

### 4. Launch Stack
```bash
# Start all services
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 5. Run First Audit
```bash
# Run AWS audit
./scripts/run-all-audits.sh

# This will take 10-30 minutes depending on your AWS environment
```

### 6. View Results
```bash
# Web interface
open http://localhost:8080/reports

# Neo4j graph
open http://localhost:7474
# Login: neo4j / <your-neo4j-password>

# Database
docker-compose exec postgresql psql -U auditor -d security_audits
```

## Additional Cloud Providers

### Azure Setup
```bash
mkdir -p credentials/azure

# Login with Azure CLI
az login

# OR create service principal credentials
cat > credentials/azure/credentials.json << EOF
{
  "clientId": "YOUR_CLIENT_ID",
  "clientSecret": "YOUR_CLIENT_SECRET",
  "tenantId": "YOUR_TENANT_ID",
  "subscriptionId": "YOUR_SUBSCRIPTION_ID"
}
EOF
```

### GCP Setup
```bash
mkdir -p credentials/gcp

# Copy service account key
cp ~/path/to/your/service-account-key.json credentials/gcp/credentials.json
```

### Kubernetes Setup
```bash
mkdir -p kubeconfigs

# Copy your kubeconfig
cp ~/.kube/config kubeconfigs/config

# Or for specific cluster
kubectl config view --flatten > kubeconfigs/config
```

## Verify Installation

```bash
# Check all containers are healthy
docker-compose ps

# View logs
docker-compose logs -f

# Test database connection
docker-compose exec postgresql psql -U auditor -d security_audits -c "SELECT version();"

# Test Neo4j
curl -u neo4j:your-password http://localhost:7474/db/data/
```

## Troubleshooting

### Port Conflicts
If ports 5432, 7474, or 8080 are in use:
```bash
# Edit .env
POSTGRES_PORT=5433
NEO4J_HTTP_PORT=7475
NGINX_PORT=8081

# Restart
docker-compose down
docker-compose up -d
```

### Permission Denied
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Fix credentials permissions
chmod 600 credentials/aws/credentials
```

### Container Won't Start
```bash
# View logs
docker-compose logs [service-name]

# Recreate container
docker-compose up -d --force-recreate [service-name]

# Reset everything
docker-compose down -v
docker-compose up -d
```

### Database Connection Failed
```bash
# Check PostgreSQL is ready
docker-compose exec postgresql pg_isready

# Reinitialize database
docker-compose down -v postgresql
docker-compose up -d postgresql
```

## Next Steps

1. Review the main [README.md](README.md) for detailed usage
2. Customize tool selection in `.env`
3. Add Cloud Custodian policies to `policies/`
4. Place IaC code in `iac-code/` for scanning
5. Export findings: `./scripts/export-findings.sh`

## Getting Help

- Check [README.md](README.md) for detailed documentation
- Review logs: `docker-compose logs -f`
- Open an issue on GitHub
- Check troubleshooting section in README.md

## Minimal Working Example

```bash
# Just want to see it work? Here's the absolute minimum:

# 1. Setup
git clone <repo> && cd cloud-security-audit-stack
cp .env.example .env
mkdir -p credentials/aws
echo -e "[default]\naws_access_key_id=YOUR_KEY\naws_secret_access_key=YOUR_SECRET" > credentials/aws/credentials

# 2. Run
docker-compose up -d
./scripts/run-all-audits.sh

# 3. View
open http://localhost:8080/reports
```

Done! Your security audit stack is now operational.
