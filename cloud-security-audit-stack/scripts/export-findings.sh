#!/bin/bash
# ============================================================================
# Cloud Security Audit Stack - Export Findings with Remediation
# ============================================================================
# This script exports findings with remediation guidance for client delivery

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_DIR/reports"
EXPORT_DIR="$REPORTS_DIR/exports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Create export directory
mkdir -p "$EXPORT_DIR"

log "========================================" 
log "Exporting Security Findings"
log "========================================"

# Check database connection
if ! docker-compose exec -T postgresql pg_isready -U auditor > /dev/null 2>&1; then
    log_warn "Database is not ready. Please ensure the stack is running."
    exit 1
fi

# Export all findings to CSV
log "Exporting all findings to CSV..."
docker-compose exec -T postgresql psql -U auditor -d security_audits << EOF > "$EXPORT_DIR/all_findings_${TIMESTAMP}.csv"
\COPY (
    SELECT 
        finding_id,
        tool,
        cloud_provider,
        resource_type,
        resource_id,
        resource_name,
        severity,
        status,
        title,
        description,
        remediation,
        scan_date
    FROM findings
    ORDER BY 
        CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END,
        scan_date DESC
) TO STDOUT WITH CSV HEADER
EOF

log "Exported all findings to: all_findings_${TIMESTAMP}.csv"

# Export critical and high findings only
log "Exporting critical and high severity findings..."
docker-compose exec -T postgresql psql -U auditor -d security_audits << EOF > "$EXPORT_DIR/critical_high_findings_${TIMESTAMP}.csv"
\COPY (
    SELECT 
        finding_id,
        tool,
        cloud_provider,
        resource_type,
        resource_id,
        resource_name,
        severity,
        title,
        description,
        remediation
    FROM findings
    WHERE severity IN ('critical', 'high')
    AND status = 'open'
    ORDER BY 
        CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
        END,
        scan_date DESC
) TO STDOUT WITH CSV HEADER
EOF

log "Exported critical/high findings to: critical_high_findings_${TIMESTAMP}.csv"

# Export findings by cloud provider
for provider in aws azure gcp kubernetes; do
    count=$(docker-compose exec -T postgresql psql -U auditor -d security_audits -t -c \
        "SELECT COUNT(*) FROM findings WHERE cloud_provider = '$provider' AND status = 'open'")
    
    if [ "$count" -gt 0 ]; then
        log "Exporting $provider findings..."
        docker-compose exec -T postgresql psql -U auditor -d security_audits << EOF > "$EXPORT_DIR/${provider}_findings_${TIMESTAMP}.csv"
\COPY (
    SELECT 
        finding_id,
        resource_type,
        resource_id,
        severity,
        title,
        remediation
    FROM findings
    WHERE cloud_provider = '$provider'
    AND status = 'open'
    ORDER BY severity, scan_date DESC
) TO STDOUT WITH CSV HEADER
EOF
        log "Exported $provider findings to: ${provider}_findings_${TIMESTAMP}.csv"
    fi
done

# Export compliance summary
log "Generating compliance summary..."
docker-compose exec -T postgresql psql -U auditor -d security_audits << EOF > "$EXPORT_DIR/compliance_summary_${TIMESTAMP}.csv"
\COPY (
    SELECT * FROM compliance_coverage
) TO STDOUT WITH CSV HEADER
EOF

log "Exported compliance summary to: compliance_summary_${TIMESTAMP}.csv"

# Generate summary report
log "Generating summary statistics..."
cat > "$EXPORT_DIR/summary_${TIMESTAMP}.txt" << EOF
Cloud Security Audit Stack - Export Summary
Generated: $(date)
============================================

FINDINGS BY SEVERITY:
$(docker-compose exec -T postgresql psql -U auditor -d security_audits -t -c "
    SELECT 
        severity,
        COUNT(*) as count,
        COUNT(*) FILTER (WHERE status = 'open') as open,
        COUNT(*) FILTER (WHERE status = 'closed') as closed
    FROM findings
    GROUP BY severity
    ORDER BY 
        CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
        END
")

FINDINGS BY CLOUD PROVIDER:
$(docker-compose exec -T postgresql psql -U auditor -d security_audits -t -c "
    SELECT 
        cloud_provider,
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'open') as open
    FROM findings
    GROUP BY cloud_provider
    ORDER BY total DESC
")

TOP 10 AFFECTED RESOURCES:
$(docker-compose exec -T postgresql psql -U auditor -d security_audits -t -c "
    SELECT 
        resource_type,
        COUNT(*) as findings_count
    FROM findings
    WHERE status = 'open'
    GROUP BY resource_type
    ORDER BY findings_count DESC
    LIMIT 10
")

COMPLIANCE FRAMEWORKS:
$(docker-compose exec -T postgresql psql -U auditor -d security_audits -t -c "
    SELECT * FROM compliance_coverage
")

FILES GENERATED:
$(ls -lh $EXPORT_DIR/*_${TIMESTAMP}.* | awk '{print "  " $9 " (" $5 ")"}')

============================================
EOF

log "Generated summary report: summary_${TIMESTAMP}.txt"

# Create a README for the export
cat > "$EXPORT_DIR/README_${TIMESTAMP}.txt" << 'EOF'
Cloud Security Audit Stack - Export Package
============================================

This package contains security findings from automated cloud and Kubernetes
security audits. Each finding includes:

- Finding ID: Unique identifier for the issue
- Tool: Security tool that detected the finding
- Cloud Provider: AWS, Azure, GCP, or Kubernetes
- Resource Information: Type, ID, and name of affected resource
- Severity: Critical, High, Medium, or Low
- Title & Description: What the issue is
- Remediation: Specific commands and steps to fix the issue

FILE DESCRIPTIONS:

1. all_findings_*.csv
   - Complete list of all findings from all tools
   - Includes all severities and statuses

2. critical_high_findings_*.csv
   - Only CRITICAL and HIGH severity findings
   - Focus on these for immediate remediation

3. [provider]_findings_*.csv
   - Findings specific to each cloud provider
   - Separate files for AWS, Azure, GCP, and Kubernetes

4. compliance_summary_*.csv
   - Compliance framework coverage
   - Shows controls checked and findings per framework

5. summary_*.txt
   - Executive summary with statistics
   - Quick overview of security posture

REMEDIATION WORKFLOW:

1. Review critical_high_findings_*.csv first
2. For each finding, execute the commands in the "remediation" column
3. Verify the fix by re-running the security audit
4. Mark findings as "closed" once remediated

NOTES:

- All remediation commands should be tested in a non-production 
  environment first
- Some remediations may require approval or change management
- Backup configurations before applying changes
- Re-run audits after remediation to verify fixes

For questions or assistance, contact your security team.
EOF

log "Created README: README_${TIMESTAMP}.txt"

# Create a zip archive
if command -v zip &> /dev/null; then
    log "Creating zip archive..."
    cd "$EXPORT_DIR"
    zip -q "security_findings_${TIMESTAMP}.zip" *_${TIMESTAMP}.*
    log "Created archive: security_findings_${TIMESTAMP}.zip"
    cd - > /dev/null
fi

log "========================================"
log "Export Complete"
log "========================================"
log "Location: $EXPORT_DIR"
log ""
log "Files exported:"
ls -lh "$EXPORT_DIR"/*_${TIMESTAMP}.* | awk '{print "  " $9 " (" $5 ")"}'
log ""
log "To view summary:"
log "  cat $EXPORT_DIR/summary_${TIMESTAMP}.txt"
