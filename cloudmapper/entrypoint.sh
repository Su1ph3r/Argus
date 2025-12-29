#!/bin/bash
set -e

# Configure CloudMapper
if [ ! -f config.json ]; then
    cat > config.json <<EOF
{
  "accounts": [
    {
      "id": "${AWS_ACCOUNT_ID:-123456789012}",
      "name": "default",
      "default": true
    }
  ]
}
EOF
fi

# Collect data
echo "Collecting AWS infrastructure data..."
python cloudmapper.py collect --account default || true

# Prepare visualization
echo "Preparing visualization..."
python cloudmapper.py prepare --account default || true

# Generate report
echo "Generating CloudMapper report..."
python cloudmapper.py weboftrust --account default > /reports/cloudmapper-report.html || true

# Copy visualization files
if [ -d "web" ]; then
    cp -r web/* /reports/ || true
fi

echo "CloudMapper scan complete. Reports saved to /reports/"
