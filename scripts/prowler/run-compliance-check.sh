#!/bin/bash
# Run Prowler compliance checks

echo "Starting Prowler compliance checks..."
echo "Timestamp: $(date)"

# Create output directory with timestamp
OUTPUT_BASE="/prowler/output"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Function to run Prowler with specific compliance framework
run_compliance_check() {
    local framework=$1
    local output_dir="${OUTPUT_BASE}/${framework}-${TIMESTAMP}"
    
    echo "Running ${framework} compliance check..."
    
    prowler aws \
        --compliance ${framework} \
        --output-formats html,json,csv \
        --output-directory "${output_dir}" \
        --log-level INFO \
        --no-banner \
        --parallel 10
    
    if [ $? -eq 0 ]; then
        echo "${framework} check completed successfully"
    else
        echo "${framework} check failed"
    fi
}

# Run multiple compliance frameworks
run_compliance_check "cis_2.0_aws"
run_compliance_check "aws_well_architected_framework"
run_compliance_check "hipaa"
run_compliance_check "gdpr"
run_compliance_check "pci_dss_v321"
run_compliance_check "soc2"

# Run custom security checks
echo "Running custom security checks..."
prowler aws \
    --categories secrets,forensics,incident_response \
    --output-formats html,json,csv \
    --output-directory "${OUTPUT_BASE}/custom-${TIMESTAMP}" \
    --log-level INFO \
    --no-banner

# Run critical severity checks only
echo "Running critical severity findings scan..."
prowler aws \
    --severity critical \
    --output-formats json \
    --output-directory "${OUTPUT_BASE}/critical-${TIMESTAMP}" \
    --quick

echo "All Prowler checks completed at $(date)"

# Generate summary report
echo "Generating summary report..."
find ${OUTPUT_BASE}/*-${TIMESTAMP} -name "*.json" -exec echo "Processing {}" \;
