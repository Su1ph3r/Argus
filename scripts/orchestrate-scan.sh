#!/bin/bash
# Orchestrate full cloud security scan

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if docker-compose is running
check_services() {
    log "Checking if services are running..."
    if ! docker-compose ps | grep -q "Up"; then
        error "Services are not running. Starting them now..."
        docker-compose up -d
        sleep 10  # Wait for services to initialize
    fi
}

# Validate credentials
validate_credentials() {
    log "Validating cloud credentials..."
    
    # Check AWS credentials
    if [ -z "$AWS_ACCESS_KEY_ID" ]; then
        warning "AWS credentials not found in environment"
    fi
    
    # Check Azure credentials
    if [ -z "$AZURE_CLIENT_ID" ]; then
        warning "Azure credentials not found in environment"
    fi
}

# Main execution
main() {
    cd "$PROJECT_ROOT"
    
    log "Starting comprehensive cloud security audit..."
    
    # Load environment variables
    if [ -f .env ]; then
        export $(cat .env | grep -v '^#' | xargs)
    else
        error ".env file not found. Copy .env.example to .env and configure credentials."
        exit 1
    fi
    
    check_services
    validate_credentials
    
    # Create report directories
    mkdir -p reports/{scoutsuite,prowler} processed-reports
    
    # Run ScoutSuite scans in parallel
    log "Starting ScoutSuite scan..."
    docker-compose exec -T scoutsuite /scripts/run-aws-audit.sh &
    SCOUT_PID=$!
    
    # Run Prowler compliance checks
    log "Starting Prowler compliance checks..."
    docker-compose exec -T prowler /scripts/run-compliance-check.sh &
    PROWLER_PID=$!
    
    # Monitor progress
    log "Monitoring scan progress..."
    
    # Wait for ScoutSuite
    if wait $SCOUT_PID; then
        log "ScoutSuite scan completed successfully"
    else
        error "ScoutSuite scan failed"
    fi
    
    # Wait for Prowler
    if wait $PROWLER_PID; then
        log "Prowler scan completed successfully"
    else
        error "Prowler scan failed"
    fi
    
    # Process and merge reports
    log "Processing and merging reports..."
    docker-compose exec -T report-processor python /app/process_reports.py
    
    # Generate summary statistics
    log "Generating summary statistics..."
    docker-compose exec -T report-processor python /app/generate_summary.py
    
    # Update Grafana dashboards
    log "Updating Grafana dashboards..."
    curl -X POST http://admin:admin@localhost:3000/api/admin/provisioning/dashboards/reload
    
    # Send notifications (if configured)
    if [ ! -z "$SLACK_WEBHOOK_URL" ]; then
        log "Sending Slack notification..."
        docker-compose exec -T report-processor python /app/send_notifications.py
    fi
    
    log "Audit complete!"
    echo ""
    echo "==================================="
    echo "  Cloud Security Audit Complete"
    echo "==================================="
    echo ""
    echo "View reports at:"
    echo "  - HTML Reports: http://localhost:8080"
    echo "  - Grafana Dashboard: http://localhost:3000"
    echo "  - Database: localhost:5432"
    echo ""
    echo "Report locations:"
    echo "  - ScoutSuite: ./reports/scoutsuite/"
    echo "  - Prowler: ./reports/prowler/"
    echo "  - Processed: ./processed-reports/"
}

# Trap errors
trap 'error "Script failed at line $LINENO"' ERR

# Run main function
main "$@"
