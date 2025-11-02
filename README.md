# Cloud Security Audit Stack

A comprehensive Docker Compose stack for automated cloud security auditing using ScoutSuite and Prowler.

## 🚀 Features

- **Multi-Cloud Support**: AWS, Azure, and GCP auditing capabilities
- **Compliance Frameworks**: CIS, PCI-DSS, HIPAA, GDPR, SOC2, and more
- **Automated Reporting**: HTML, JSON, and CSV output formats
- **Database Storage**: PostgreSQL for historical tracking
- **Visual Dashboards**: Grafana for metrics visualization
- **Web Interface**: Nginx for easy report viewing
- **Containerized**: Fully dockerized for easy deployment

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Cloud credentials (AWS, Azure, or GCP)
- 4GB RAM minimum
- 10GB disk space

## 🛠️ Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/cloud-audit-stack.git
cd cloud-audit-stack
```

### 2. Configure Credentials

```bash
cp .env.example .env
# Edit .env with your cloud credentials
nano .env
```

### 3. Start the Stack

```bash
# Start all services
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 4. Run Your First Audit

```bash
# Run complete audit
./scripts/orchestrate-scan.sh

# Or run individual tools
docker-compose exec scoutsuite /scripts/run-aws-audit.sh
docker-compose exec prowler /scripts/run-compliance-check.sh
```

### 5. View Results

- **HTML Reports**: http://localhost:8080
- **Grafana Dashboard**: http://localhost:3000 (admin/admin)
- **PostgreSQL**: localhost:5432

## 📁 Project Structure

```
cloud-audit-stack/
├── docker-compose.yml           # Main orchestration file
├── .env.example                 # Environment variables template
├── scripts/
│   ├── orchestrate-scan.sh     # Main execution script
│   ├── scoutsuite/
│   │   └── run-aws-audit.sh    # ScoutSuite scripts
│   └── prowler/
│       └── run-compliance-check.sh  # Prowler scripts
├── report-processor/
│   ├── Dockerfile              # Custom processor image
│   ├── requirements.txt        # Python dependencies
│   └── process_reports.py      # Report processing logic
├── db-init/
│   └── 01-schema.sql          # Database schema
├── nginx-config/
│   └── default.conf           # Web server configuration
└── reports/                   # Generated reports (gitignored)
```

## 🔧 Configuration

### Environment Variables

Key environment variables in `.env`:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AWS_DEFAULT_REGION=us-east-1

# Azure Configuration  
AZURE_SUBSCRIPTION_ID=your-subscription
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-secret
AZURE_TENANT_ID=your-tenant

# Database
DB_PASSWORD=secure-password

# Grafana
GRAFANA_USER=admin
GRAFANA_PASSWORD=secure-password
```

### Customizing Scans

Edit the scan scripts in `scripts/` to customize:
- Compliance frameworks to check
- Regions to scan
- Resource types to audit
- Output formats

## 📊 Compliance Frameworks

### Prowler Supported Frameworks
- CIS AWS Foundations Benchmark 2.0
- AWS Well-Architected Framework
- PCI-DSS v3.2.1
- HIPAA
- GDPR
- SOC2
- ISO 27001
- NIST 800-53

### ScoutSuite Coverage
- AWS: All major services
- Azure: Core services
- GCP: Essential services

## 🚀 Advanced Usage

### Running Specific Compliance Checks

```bash
# CIS Benchmark only
docker-compose exec prowler prowler aws --compliance cis_2.0_aws

# Critical findings only
docker-compose exec prowler prowler aws --severity critical

# Specific service audit
docker-compose exec scoutsuite scout aws --services s3
```

### Multi-Account Scanning

```bash
# AWS profiles
for profile in dev staging prod; do
    docker-compose exec scoutsuite scout aws --profile $profile
done

# Azure subscriptions
docker-compose exec scoutsuite scout azure --all-subscriptions
```

### Scheduling with Cron

```bash
# Add to crontab for daily scans
0 2 * * * /path/to/cloud-audit-stack/scripts/orchestrate-scan.sh
```

### Database Queries

```sql
-- Connect to database
psql -h localhost -U audituser -d cloudaudit

-- Recent critical findings
SELECT * FROM v_recent_critical_findings;

-- Compliance trends
SELECT * FROM get_compliance_trend('cis_2.0_aws', 30);

-- Finding statistics by region
SELECT region, severity, COUNT(*) 
FROM findings 
GROUP BY region, severity 
ORDER BY region, severity;
```

## 🔍 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   chmod +x scripts/*.sh scripts/**/*.sh
   ```

2. **Database Connection Failed**
   ```bash
   docker-compose restart postgres
   docker-compose logs postgres
   ```

3. **No Reports Generated**
   ```bash
   # Check container logs
   docker-compose logs scoutsuite
   docker-compose logs prowler
   ```

4. **Out of Memory**
   ```yaml
   # Add to docker-compose.yml
   services:
     scoutsuite:
       mem_limit: 2g
   ```

## 🔒 Security Considerations

- Never commit `.env` files with real credentials
- Use read-only mounts for credential directories
- Rotate cloud access keys regularly
- Restrict database access in production
- Enable TLS for external access
- Review and limit IAM permissions

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) by NCC Group
- [Prowler](https://github.com/prowler-cloud/prowler) by Toni de la Fuente
- Docker and Docker Compose communities

## 📧 Support

- Create an issue for bugs
- Discussions for questions
- Wiki for documentation

## 🗺️ Roadmap

- [ ] Kubernetes support
- [ ] Additional cloud providers (Oracle, IBM)
- [ ] AI-powered finding prioritization
- [ ] Automated remediation scripts
- [ ] Integration with ticketing systems
- [ ] Real-time monitoring capabilities

---

**Last Updated**: 2024
**Version**: 1.0.0
