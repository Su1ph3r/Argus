#!/bin/bash
# ============================================================================
# Cloud Security Audit Stack - Run All Audits
# ============================================================================
# This script runs all configured security audits across all cloud providers
# and Kubernetes environments

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_DIR/reports"
LOG_FILE="$PROJECT_DIR/logs/audit-$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE"
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE"
            ;;
        *)
            echo -e "${BLUE}[$level]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Check if Docker Compose is running
check_docker() {
    if ! docker-compose ps >/dev/null 2>&1; then
        log ERROR "Docker Compose is not running. Please start the stack first:"
        log ERROR "  docker-compose up -d"
        exit 1
    fi
}

# Run AWS audits
run_aws_audits() {
    log INFO "========================================" 
    log INFO "Running AWS Security Audits"
    log INFO "========================================"
    
    # Check if AWS credentials exist
    if [ ! -f "$PROJECT_DIR/credentials/aws/credentials" ]; then
        log WARN "AWS credentials not found. Skipping AWS audits."
        return
    fi
    
    # Prowler
    if [ "${ENABLE_PROWLER:-true}" = "true" ]; then
        log INFO "Running Prowler..."
        docker-compose run --rm prowler aws \
            --output-modes json,html,csv \
            --output-directory /reports \
            --severity critical high medium low \
            --log-file /logs/prowler.log || log ERROR "Prowler failed"
    fi
    
    # ScoutSuite
    if [ "${ENABLE_SCOUTSUITE:-true}" = "true" ]; then
        log INFO "Running ScoutSuite for AWS..."
        docker-compose run --rm scoutsuite-aws || log ERROR "ScoutSuite AWS failed"
    fi
    
    # CloudSploit
    if [ "${ENABLE_CLOUDSPLOIT:-true}" = "true" ]; then
        log INFO "Running CloudSploit for AWS..."
        docker-compose run --rm cloudsploit || log ERROR "CloudSploit failed"
    fi
    
    # Cloud Custodian
    if [ "${ENABLE_CUSTODIAN:-true}" = "true" ]; then
        log INFO "Running Cloud Custodian..."
        if [ -d "$PROJECT_DIR/policies" ] && [ "$(ls -A $PROJECT_DIR/policies/*.yml 2>/dev/null)" ]; then
            docker-compose run --rm cloud-custodian || log ERROR "Cloud Custodian failed"
        else
            log WARN "No Cloud Custodian policies found in ./policies/"
        fi
    fi
    
    # CloudMapper
    if [ "${ENABLE_CLOUDMAPPER:-true}" = "true" ]; then
        log INFO "Running CloudMapper..."
        docker-compose run --rm cloudmapper || log ERROR "CloudMapper failed"
    fi
    
    # Cartography
    if [ "${ENABLE_CARTOGRAPHY:-true}" = "true" ]; then
        log INFO "Running Cartography..."
        docker-compose run --rm cartography || log ERROR "Cartography failed"
    fi
    
    log INFO "AWS audits complete"
}

# Run Kubernetes audits
run_kubernetes_audits() {
    log INFO "========================================"
    log INFO "Running Kubernetes Security Audits"
    log INFO "========================================"
    
    # Check if kubeconfig exists
    if [ ! -f "$PROJECT_DIR/kubeconfigs/config" ]; then
        log WARN "Kubernetes config not found. Skipping K8s audits."
        return
    fi
    
    # kube-bench
    if [ "${ENABLE_KUBE_BENCH:-true}" = "true" ]; then
        log INFO "Running kube-bench..."
        docker-compose run --rm kube-bench || log ERROR "kube-bench failed"
    fi
    
    # Kubescape
    if [ "${ENABLE_KUBESCAPE:-true}" = "true" ]; then
        log INFO "Running Kubescape..."
        docker-compose run --rm kubescape || log ERROR "Kubescape failed"
    fi
    
    # kube-hunter
    if [ "${ENABLE_KUBE_HUNTER:-false}" = "true" ]; then
        log WARN "Running kube-hunter (active testing)..."
        docker-compose run --rm kube-hunter || log ERROR "kube-hunter failed"
    fi
    
    # Trivy
    if [ "${ENABLE_TRIVY:-true}" = "true" ]; then
        log INFO "Running Trivy for Kubernetes..."
        docker-compose run --rm trivy config /kubeconfigs --output /reports/trivy/k8s-config-scan.json || log ERROR "Trivy failed"
    fi
    
    # Popeye
    if [ "${ENABLE_POPEYE:-true}" = "true" ]; then
        log INFO "Running Popeye..."
        docker-compose run --rm popeye || log ERROR "Popeye failed"
    fi
    
    log INFO "Kubernetes audits complete"
}

# Run IaC scans
run_iac_scans() {
    log INFO "========================================"
    log INFO "Running Infrastructure-as-Code Scans"
    log INFO "========================================"
    
    # Check if IaC code exists
    if [ ! -d "$PROJECT_DIR/iac-code" ] || [ -z "$(ls -A $PROJECT_DIR/iac-code 2>/dev/null)" ]; then
        log WARN "No IaC code found in ./iac-code/. Skipping IaC scans."
        return
    fi
    
    # Checkov
    if [ "${ENABLE_CHECKOV:-true}" = "true" ]; then
        log INFO "Running Checkov..."
        docker-compose run --rm checkov || log ERROR "Checkov failed"
    fi
    
    # Terrascan
    if [ "${ENABLE_TERRASCAN:-true}" = "true" ]; then
        log INFO "Running Terrascan..."
        docker-compose run --rm terrascan || log ERROR "Terrascan failed"
    fi
    
    # tfsec
    if [ "${ENABLE_TFSEC:-true}" = "true" ]; then
        log INFO "Running tfsec..."
        docker-compose run --rm tfsec || log ERROR "tfsec failed"
    fi
    
    log INFO "IaC scans complete"
}

# Run container image scans
run_container_scans() {
    log INFO "========================================"
    log INFO "Running Container Image Scans"
    log INFO "========================================"
    
    # Get list of local images
    local images=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" | head -5)
    
    if [ -z "$images" ]; then
        log WARN "No Docker images found locally. Skipping container scans."
        return
    fi
    
    # Trivy image scans
    if [ "${ENABLE_TRIVY:-true}" = "true" ]; then
        log INFO "Running Trivy image scans..."
        for image in $images; do
            log INFO "Scanning image: $image"
            docker-compose run --rm trivy image "$image" \
                --format json \
                --output "/reports/trivy/$(echo $image | tr '/:' '_').json" || log ERROR "Trivy image scan failed for $image"
        done
    fi
    
    # Grype image scans
    if [ "${ENABLE_GRYPE:-true}" = "true" ]; then
        log INFO "Running Grype image scans..."
        for image in $images; do
            log INFO "Scanning image: $image"
            docker-compose run --rm grype "$image" \
                -o json \
                > "$REPORTS_DIR/grype/$(echo $image | tr '/:' '_').json" || log ERROR "Grype image scan failed for $image"
        done
    fi
    
    log INFO "Container scans complete"
}

# Generate summary report
generate_summary() {
    log INFO "========================================"
    log INFO "Generating Summary Report"
    log INFO "========================================"
    
    local summary_file="$REPORTS_DIR/summary-$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "Cloud Security Audit Stack - Summary Report"
        echo "Generated: $(date)"
        echo "==========================================="
        echo ""
        
        # Count findings by tool
        echo "Findings by Tool:"
        find "$REPORTS_DIR" -name "*.json" -type f | while read file; do
            local tool=$(basename $(dirname "$file"))
            local count=$(jq '. | length' "$file" 2>/dev/null || echo "0")
            echo "  $tool: $count findings"
        done
        echo ""
        
        # Report locations
        echo "Reports available at:"
        echo "  Web Interface: http://localhost:${NGINX_PORT:-8080}/reports"
        echo "  Neo4j Graph: http://localhost:${NEO4J_HTTP_PORT:-7474}"
        echo "  PostgreSQL: docker-compose exec postgresql psql -U auditor -d security_audits"
        echo "  File System: $REPORTS_DIR"
        echo ""
        
    } | tee "$summary_file"
    
    log INFO "Summary report saved to: $summary_file"
}

# Main execution
main() {
    log INFO "========================================"
    log INFO "Cloud Security Audit Stack"
    log INFO "Starting Full Security Audit"
    log INFO "========================================"
    log INFO "Start time: $(date)"
    echo ""
    
    # Load environment variables
    if [ -f "$PROJECT_DIR/.env" ]; then
        set -a
        source "$PROJECT_DIR/.env"
        set +a
    fi
    
    # Check prerequisites
    check_docker
    
    # Create reports directory
    mkdir -p "$REPORTS_DIR"
    
    # Run audits
    run_aws_audits
    echo ""
    
    run_kubernetes_audits
    echo ""
    
    run_iac_scans
    echo ""
    
    run_container_scans
    echo ""
    
    # Generate summary
    generate_summary
    
    log INFO "========================================"
    log INFO "All Audits Complete"
    log INFO "End time: $(date)"
    log INFO "========================================"
    log INFO "View reports at: http://localhost:${NGINX_PORT:-8080}/reports"
    log INFO "Full log: $LOG_FILE"
}

# Run main function
main "$@"
