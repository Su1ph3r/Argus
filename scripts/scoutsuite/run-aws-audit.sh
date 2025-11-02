#!/bin/bash
# Run ScoutSuite AWS audit

echo "Starting ScoutSuite AWS audit..."
echo "Timestamp: $(date)"

# Create output directory with timestamp
OUTPUT_DIR="/opt/scoutsuite-report/aws-$(date +%Y%m%d-%H%M%S)"

# Run Scout with comprehensive options
scout aws \
  --no-browser \
  --report-dir "$OUTPUT_DIR" \
  --report-name aws-audit \
  --force \
  --max-workers 10 \
  --ruleset default.json

# Check exit status
if [ $? -eq 0 ]; then
    echo "ScoutSuite AWS audit completed successfully"
    echo "Report saved to: $OUTPUT_DIR"
else
    echo "ScoutSuite AWS audit failed with exit code: $?"
    exit 1
fi

# Optional: Run additional cloud providers
# Uncomment to enable

# Azure audit
# if [ ! -z "$AZURE_SUBSCRIPTION_ID" ]; then
#     echo "Starting Azure audit..."
#     scout azure --cli \
#         --report-dir "/opt/scoutsuite-report/azure-$(date +%Y%m%d-%H%M%S)" \
#         --report-name azure-audit
# fi

# GCP audit
# if [ -f "/root/.gcp/credentials.json" ]; then
#     echo "Starting GCP audit..."
#     scout gcp --service-account /root/.gcp/credentials.json \
#         --report-dir "/opt/scoutsuite-report/gcp-$(date +%Y%m%d-%H%M%S)" \
#         --report-name gcp-audit
# fi
