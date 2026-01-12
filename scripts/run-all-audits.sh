#!/bin/bash
# ============================================================================
# Nubicustos - Run All Audits
# ============================================================================
# This script runs all configured security audits across all cloud providers
# and Kubernetes environments

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_DIR/reports"
LOG_FILE="$PROJECT_DIR/logs/audit-$(date +%Y%m%d_%H%M%S).log"

# CLI Options (defaults)
DRY_RUN=false
SEVERITY_FILTER=""
OUTPUT_FORMAT="default"
PROFILE=""
SELECTED_PROVIDER=""
SELECTED_TOOLS=""
EXECUTED_TOOLS=()
TOTAL_FINDINGS=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# Provider to tools mapping
AWS_TOOLS="prowler,scoutsuite,cloudsploit,custodian,cloudmapper,cartography,pacu,cloudfox,enumerate-iam"
AZURE_TOOLS="prowler,scoutsuite,cloudfox"
GCP_TOOLS="prowler,scoutsuite,cloudfox,cartography"
KUBERNETES_TOOLS="kube-bench,kubescape,kube-hunter,trivy,grype,popeye,kube-linter,polaris,falco"
IAC_TOOLS="checkov,terrascan,tfsec"

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

# Show help
show_help() {
    cat << EOF
Nubicustos - Run All Audits

Usage: $(basename "$0") [OPTIONS]

Options:
    --dry-run           Show commands without executing them
    --severity LEVELS   Filter by severity (comma-separated: critical,high,medium,low)
    --output FORMAT     Output format: default, json
    --profile NAME      Use scan profile (quick, comprehensive, compliance-only)
    --provider NAME     Single provider to scan (aws, azure, gcp, kubernetes, iac)
    --tools TOOLS       Comma-separated tools to run (overrides profile)
    -h, --help          Show this help message

Examples:
    $(basename "$0") --dry-run
    $(basename "$0") --severity critical,high
    $(basename "$0") --output json --profile quick
    $(basename "$0") --provider aws --tools prowler,scoutsuite
    $(basename "$0") --provider azure --tools prowler,scoutsuite --dry-run
    $(basename "$0") --provider kubernetes --tools kubescape,trivy

Available Tools by Provider:
    aws:        prowler, scoutsuite, cloudsploit, custodian, cloudmapper,
                cartography, pacu, cloudfox, enumerate-iam
    azure:      prowler, scoutsuite, cloudfox
    gcp:        prowler, scoutsuite, cloudfox, cartography
    kubernetes: kube-bench, kubescape, kube-hunter, trivy, grype,
                popeye, kube-linter, polaris, falco
    iac:        checkov, terrascan, tfsec

Environment Variables:
    ENABLE_PROWLER, ENABLE_SCOUTSUITE, ENABLE_CLOUDSPLOIT, etc.
    See .env.example for full list

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --severity)
                SEVERITY_FILTER="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --profile|-p)
                PROFILE="$2"
                shift 2
                ;;
            --provider)
                SELECTED_PROVIDER="$2"
                shift 2
                ;;
            --tools)
                SELECTED_TOOLS="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log WARN "Unknown option: $1"
                shift
                ;;
        esac
    done
}

# Validate selected tools against available tools for provider
validate_tools() {
    local provider=$1
    local tools=$2
    local available_tools

    case $provider in
        aws) available_tools=$AWS_TOOLS ;;
        azure) available_tools=$AZURE_TOOLS ;;
        gcp) available_tools=$GCP_TOOLS ;;
        kubernetes) available_tools=$KUBERNETES_TOOLS ;;
        iac) available_tools=$IAC_TOOLS ;;
        *)
            log ERROR "Unknown provider: $provider"
            log INFO "Available providers: aws, azure, gcp, kubernetes, iac"
            return 1
            ;;
    esac

    # Validate each tool
    IFS=',' read -ra tool_array <<< "$tools"
    for tool in "${tool_array[@]}"; do
        if ! echo ",$available_tools," | grep -q ",$tool,"; then
            log ERROR "Tool '$tool' not available for provider '$provider'"
            log INFO "Available tools: $available_tools"
            return 1
        fi
    done
    return 0
}

# Apply tool selection - disable all tools then enable only selected ones
apply_tool_selection() {
    local tools=$1

    # Disable all tools first
    export ENABLE_PROWLER=false
    export ENABLE_SCOUTSUITE=false
    export ENABLE_CLOUDSPLOIT=false
    export ENABLE_CUSTODIAN=false
    export ENABLE_CLOUDMAPPER=false
    export ENABLE_CARTOGRAPHY=false
    export ENABLE_PACU=false
    export ENABLE_CLOUDFOX=false
    export ENABLE_ENUMERATE_IAM=false
    export ENABLE_KUBE_BENCH=false
    export ENABLE_KUBESCAPE=false
    export ENABLE_KUBE_HUNTER=false
    export ENABLE_TRIVY=false
    export ENABLE_GRYPE=false
    export ENABLE_POPEYE=false
    export ENABLE_KUBE_LINTER=false
    export ENABLE_POLARIS=false
    export ENABLE_FALCO=false
    export ENABLE_CHECKOV=false
    export ENABLE_TERRASCAN=false
    export ENABLE_TFSEC=false

    # Enable only selected tools
    IFS=',' read -ra tool_array <<< "$tools"
    for tool in "${tool_array[@]}"; do
        local var_name
        # Convert tool name to env variable format (e.g., kube-bench -> ENABLE_KUBE_BENCH)
        var_name="ENABLE_$(echo "$tool" | tr '[:lower:]-' '[:upper:]_')"
        export "$var_name"=true
        log INFO "Enabled tool: $tool"
    done
}

# Run tool with dry-run support
run_tool() {
    local tool_name=$1
    shift
    local command="$@"

    EXECUTED_TOOLS+=("$tool_name")

    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY-RUN] Would execute: docker-compose run --rm $command"
        return 0
    else
        docker-compose run --rm $command || {
            log ERROR "$tool_name failed"
            return 1
        }
    fi
}

# Get severity flag for tools that support it
get_severity_flag() {
    if [ -n "$SEVERITY_FILTER" ]; then
        echo "--severity $(echo $SEVERITY_FILTER | tr ',' ' ')"
    else
        echo "--severity critical high medium low"
    fi
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
        log INFO "Running Prowler for AWS..."
        run_tool "prowler" prowler aws \
            --output-formats json-ocsf csv html \
            --output-directory /reports \
            $(get_severity_flag) \
            --log-file /logs/prowler.log
    fi

    # ScoutSuite
    if [ "${ENABLE_SCOUTSUITE:-true}" = "true" ]; then
        log INFO "Running ScoutSuite for AWS..."
        run_tool "scoutsuite-aws" scoutsuite-aws
    fi

    # CloudSploit
    if [ "${ENABLE_CLOUDSPLOIT:-true}" = "true" ]; then
        log INFO "Running CloudSploit for AWS..."
        run_tool "cloudsploit" cloudsploit
    fi

    # Cloud Custodian
    if [ "${ENABLE_CUSTODIAN:-true}" = "true" ]; then
        log INFO "Running Cloud Custodian..."
        if [ -d "$PROJECT_DIR/policies" ] && [ "$(ls -A $PROJECT_DIR/policies/*.yml 2>/dev/null)" ]; then
            run_tool "cloud-custodian" cloud-custodian
        else
            log WARN "No Cloud Custodian policies found in ./policies/"
        fi
    fi

    # CloudMapper
    if [ "${ENABLE_CLOUDMAPPER:-true}" = "true" ]; then
        log INFO "Running CloudMapper..."
        run_tool "cloudmapper" cloudmapper
    fi

    # Cartography (AWS)
    if [ "${ENABLE_CARTOGRAPHY:-true}" = "true" ]; then
        log INFO "Running Cartography for AWS..."
        run_tool "cartography" cartography
    fi

    # CloudFox (AWS)
    if [ "${ENABLE_CLOUDFOX:-false}" = "true" ]; then
        log INFO "Running CloudFox for AWS..."
        run_tool "cloudfox" cloudfox aws
    fi

    log INFO "AWS audits complete"
}

# Run Azure audits
run_azure_audits() {
    log INFO "========================================"
    log INFO "Running Azure Security Audits"
    log INFO "========================================"

    # Check if Azure credentials exist
    if [ ! -d "$PROJECT_DIR/credentials/azure" ]; then
        log WARN "Azure credentials not found. Skipping Azure audits."
        return
    fi

    # Prowler (Azure)
    if [ "${ENABLE_PROWLER:-true}" = "true" ]; then
        log INFO "Running Prowler for Azure..."
        run_tool "prowler" prowler azure \
            --output-formats json-ocsf csv html \
            --output-directory /reports \
            $(get_severity_flag) \
            --log-file /logs/prowler-azure.log
    fi

    # ScoutSuite (Azure)
    if [ "${ENABLE_SCOUTSUITE:-true}" = "true" ]; then
        log INFO "Running ScoutSuite for Azure..."
        run_tool "scoutsuite" scoutsuite azure --report-dir /reports/scoutsuite
    fi

    # CloudFox (Azure)
    if [ "${ENABLE_CLOUDFOX:-false}" = "true" ]; then
        log INFO "Running CloudFox for Azure..."
        run_tool "cloudfox" cloudfox azure
    fi

    log INFO "Azure audits complete"
}

# Run GCP audits
run_gcp_audits() {
    log INFO "========================================"
    log INFO "Running GCP Security Audits"
    log INFO "========================================"

    # Check if GCP credentials exist
    if [ ! -d "$PROJECT_DIR/credentials/gcp" ]; then
        log WARN "GCP credentials not found. Skipping GCP audits."
        return
    fi

    # Prowler (GCP)
    if [ "${ENABLE_PROWLER:-true}" = "true" ]; then
        log INFO "Running Prowler for GCP..."
        run_tool "prowler" prowler gcp \
            --output-formats json-ocsf csv html \
            --output-directory /reports \
            $(get_severity_flag) \
            --log-file /logs/prowler-gcp.log
    fi

    # ScoutSuite (GCP)
    if [ "${ENABLE_SCOUTSUITE:-true}" = "true" ]; then
        log INFO "Running ScoutSuite for GCP..."
        run_tool "scoutsuite" scoutsuite gcp --report-dir /reports/scoutsuite
    fi

    # CloudFox (GCP)
    if [ "${ENABLE_CLOUDFOX:-false}" = "true" ]; then
        log INFO "Running CloudFox for GCP..."
        run_tool "cloudfox" cloudfox gcp
    fi

    # Cartography (GCP)
    if [ "${ENABLE_CARTOGRAPHY:-true}" = "true" ]; then
        log INFO "Running Cartography for GCP..."
        run_tool "cartography" cartography --gcp-project-id "$GCP_PROJECT_ID"
    fi

    log INFO "GCP audits complete"
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
        run_tool "kube-bench" kube-bench
    fi

    # Kubescape
    if [ "${ENABLE_KUBESCAPE:-true}" = "true" ]; then
        log INFO "Running Kubescape..."
        run_tool "kubescape" kubescape
    fi

    # kube-hunter
    if [ "${ENABLE_KUBE_HUNTER:-false}" = "true" ]; then
        log WARN "Running kube-hunter (active testing)..."
        run_tool "kube-hunter" kube-hunter
    fi

    # Trivy
    if [ "${ENABLE_TRIVY:-true}" = "true" ]; then
        log INFO "Running Trivy for Kubernetes..."
        run_tool "trivy" trivy config /kubeconfigs --output /reports/trivy/k8s-config-scan.json
    fi

    # Popeye
    if [ "${ENABLE_POPEYE:-true}" = "true" ]; then
        log INFO "Running Popeye..."
        run_tool "popeye" popeye
    fi

    # kube-linter
    if [ "${ENABLE_KUBE_LINTER:-true}" = "true" ]; then
        log INFO "Running kube-linter..."
        if [ -d "$PROJECT_DIR/iac-code" ]; then
            run_tool "kube-linter" kube-linter
        else
            log WARN "No manifests found for kube-linter"
        fi
    fi

    # Polaris
    if [ "${ENABLE_POLARIS:-true}" = "true" ]; then
        log INFO "Running Polaris..."
        if [ -d "$PROJECT_DIR/iac-code" ]; then
            run_tool "polaris" polaris
        else
            log WARN "No manifests found for Polaris"
        fi
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
        run_tool "checkov" checkov
    fi

    # Terrascan
    if [ "${ENABLE_TERRASCAN:-true}" = "true" ]; then
        log INFO "Running Terrascan..."
        run_tool "terrascan" terrascan
    fi

    # tfsec
    if [ "${ENABLE_TFSEC:-true}" = "true" ]; then
        log INFO "Running tfsec..."
        run_tool "tfsec" tfsec
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
            run_tool "trivy" trivy image "$image" \
                --format json \
                --output "/reports/trivy/$(echo $image | tr '/:' '_').json"
        done
    fi

    # Grype image scans
    if [ "${ENABLE_GRYPE:-true}" = "true" ]; then
        log INFO "Running Grype image scans..."
        for image in $images; do
            log INFO "Scanning image: $image"
            if [ "$DRY_RUN" = "true" ]; then
                log INFO "[DRY-RUN] Would execute: docker-compose run --rm grype $image -o json > $REPORTS_DIR/grype/$(echo $image | tr '/:' '_').json"
            else
                docker-compose run --rm grype "$image" \
                    -o json \
                    > "$REPORTS_DIR/grype/$(echo $image | tr '/:' '_').json" || log ERROR "Grype image scan failed for $image"
            fi
            EXECUTED_TOOLS+=("grype")
        done
    fi
    
    log INFO "Container scans complete"
}

# Generate summary report
generate_summary() {
    log INFO "========================================"
    log INFO "Generating Summary Report"
    log INFO "========================================"

    local timestamp=$(date -Iseconds)
    local summary_file="$REPORTS_DIR/summary-$(date +%Y%m%d_%H%M%S).txt"
    local json_summary_file="$REPORTS_DIR/summary_latest.json"

    # Count findings from JSON reports
    local total=0
    local critical=0
    local high=0
    local medium=0
    local low=0

    # Parse existing JSON reports for severity counts
    for json_file in $(find "$REPORTS_DIR" -name "*.json" -type f 2>/dev/null); do
        if [ -f "$json_file" ]; then
            # Try to count findings - different tools have different formats
            local count=$(jq 'if type == "array" then length elif type == "object" and .findings then .findings | length else 0 end' "$json_file" 2>/dev/null || echo "0")
            total=$((total + count))

            # Try to count by severity (Prowler format)
            critical=$((critical + $(jq '[.[] | select(.Severity == "critical" or .severity == "critical")] | length' "$json_file" 2>/dev/null || echo "0")))
            high=$((high + $(jq '[.[] | select(.Severity == "high" or .severity == "high")] | length' "$json_file" 2>/dev/null || echo "0")))
            medium=$((medium + $(jq '[.[] | select(.Severity == "medium" or .severity == "medium")] | length' "$json_file" 2>/dev/null || echo "0")))
            low=$((low + $(jq '[.[] | select(.Severity == "low" or .severity == "low")] | length' "$json_file" 2>/dev/null || echo "0")))
        fi
    done

    # Generate text summary
    {
        echo "Cloud Security Audit Stack - Summary Report"
        echo "Generated: $(date)"
        echo "==========================================="
        echo ""

        echo "Tools Executed: ${#EXECUTED_TOOLS[@]}"
        echo "  ${EXECUTED_TOOLS[*]:-none}"
        echo ""

        echo "Findings Summary:"
        echo "  Total:    $total"
        echo "  Critical: $critical"
        echo "  High:     $high"
        echo "  Medium:   $medium"
        echo "  Low:      $low"
        echo ""

        # Report locations
        echo "Reports available at:"
        echo "  Web Interface: http://localhost:${NGINX_PORT:-8080}/reports"
        echo "  Neo4j Graph: http://localhost:${NEO4J_HTTP_PORT:-7474}"
        echo "  PostgreSQL: docker-compose exec postgresql psql -U auditor -d security_audits"
        echo "  File System: $REPORTS_DIR"
        echo ""

    } | tee "$summary_file"

    # Always generate JSON summary for the web interface badges
    cat > "$json_summary_file" << EOF
{
    "timestamp": "$timestamp",
    "dry_run": $DRY_RUN,
    "severity_filter": "${SEVERITY_FILTER:-all}",
    "profile": "${PROFILE:-default}",
    "tools_executed": [$(printf '"%s",' "${EXECUTED_TOOLS[@]}" | sed 's/,$//')],
    "findings": {
        "total": $total,
        "critical": $critical,
        "high": $high,
        "medium": $medium,
        "low": $low
    }
}
EOF

    # Generate additional JSON output if requested
    if [ "$OUTPUT_FORMAT" = "json" ]; then
        log INFO "JSON output mode - summary written to: $json_summary_file"
        cat "$json_summary_file"
    fi

    log INFO "Summary report saved to: $summary_file"
    log INFO "JSON summary saved to: $json_summary_file"
}

# Main execution
main() {
    # Parse command line arguments first
    parse_args "$@"

    log INFO "========================================"
    log INFO "Nubicustos - Cloud Security Platform"
    log INFO "Starting Security Audit"
    log INFO "========================================"
    log INFO "Start time: $(date)"

    # Show configuration
    if [ "$DRY_RUN" = "true" ]; then
        log WARN "DRY RUN MODE - Commands will be shown but not executed"
    fi
    if [ -n "$SEVERITY_FILTER" ]; then
        log INFO "Severity filter: $SEVERITY_FILTER"
    fi
    if [ -n "$PROFILE" ]; then
        log INFO "Using scan profile: $PROFILE"
    fi
    if [ -n "$SELECTED_PROVIDER" ]; then
        log INFO "Selected provider: $SELECTED_PROVIDER"
    fi
    if [ -n "$SELECTED_TOOLS" ]; then
        log INFO "Selected tools: $SELECTED_TOOLS"
    fi
    echo ""

    # Load environment variables
    if [ -f "$PROJECT_DIR/.env" ]; then
        set -a
        source "$PROJECT_DIR/.env"
        set +a
    fi

    # Load scan profile if specified (overrides .env settings)
    if [ -n "$PROFILE" ] && [ -f "$SCRIPT_DIR/profile-loader.sh" ]; then
        log INFO "Loading profile: $PROFILE"
        source "$SCRIPT_DIR/profile-loader.sh"
        eval "$(load_profile "$PROFILE")"
    fi

    # Validate and apply tool selection if specified
    if [ -n "$SELECTED_TOOLS" ]; then
        if [ -z "$SELECTED_PROVIDER" ]; then
            log ERROR "--tools requires --provider to be specified"
            exit 1
        fi
        if ! validate_tools "$SELECTED_PROVIDER" "$SELECTED_TOOLS"; then
            exit 1
        fi
        apply_tool_selection "$SELECTED_TOOLS"
    fi

    # Check prerequisites
    check_docker

    # Create reports directory
    mkdir -p "$REPORTS_DIR"

    # Run audits based on provider selection
    if [ -n "$SELECTED_PROVIDER" ]; then
        # Run only the selected provider
        case $SELECTED_PROVIDER in
            aws)
                run_aws_audits
                ;;
            azure)
                run_azure_audits
                ;;
            gcp)
                run_gcp_audits
                ;;
            kubernetes)
                run_kubernetes_audits
                ;;
            iac)
                run_iac_scans
                ;;
            *)
                log ERROR "Unknown provider: $SELECTED_PROVIDER"
                exit 1
                ;;
        esac
    else
        # Run all audits (default behavior)
        run_aws_audits
        echo ""

        run_kubernetes_audits
        echo ""

        run_iac_scans
        echo ""

        run_container_scans
    fi
    echo ""

    # Generate summary
    generate_summary

    # Load findings into database
    log INFO "========================================"
    log INFO "Loading Findings into Database"
    log INFO "========================================"
    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY-RUN] Would execute: docker-compose exec -T report-processor python /app/process_reports.py"
    else
        log INFO "Processing and loading scan reports..."
        docker-compose exec -T report-processor python /app/process_reports.py || {
            log ERROR "Failed to load findings into database"
        }
        log INFO "Database loading complete"
    fi

    log INFO "========================================"
    log INFO "All Audits Complete"
    log INFO "End time: $(date)"
    log INFO "========================================"
    log INFO "View reports at: http://localhost:${NGINX_PORT:-8080}/reports"
    log INFO "Full log: $LOG_FILE"
}

# Run main function
main "$@"
