#!/bin/bash
# Setup script for Linux deployments of Nubicustos
# Fixes permission issues with credential storage

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Nubicustos Linux Permission Setup"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Running as root - will set permissions for API user (UID 1000)"
else
    echo "Note: Some operations may require sudo. Run with sudo if you encounter permission errors."
fi

# Create credentials directories if they don't exist
echo ""
echo "Creating credentials directories..."
mkdir -p "$PROJECT_ROOT/credentials/aws"
mkdir -p "$PROJECT_ROOT/credentials/azure"

# Create other required directories
echo "Creating other required directories..."
mkdir -p "$PROJECT_ROOT/reports"
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/iac-staging"

# Set ownership to UID 1000 (the API container user)
echo ""
echo "Setting ownership to UID 1000 (API container user)..."

if [ "$EUID" -eq 0 ]; then
    chown -R 1000:1000 "$PROJECT_ROOT/credentials"
    chown -R 1000:1000 "$PROJECT_ROOT/iac-staging"
    # Reports needs to be writable by multiple containers
    chmod -R 777 "$PROJECT_ROOT/reports"
    chmod -R 777 "$PROJECT_ROOT/logs"
    echo "Permissions set successfully."
else
    echo "Run the following commands with sudo to set permissions:"
    echo ""
    echo "  sudo chown -R 1000:1000 $PROJECT_ROOT/credentials"
    echo "  sudo chown -R 1000:1000 $PROJECT_ROOT/iac-staging"
    echo "  sudo chmod -R 777 $PROJECT_ROOT/reports"
    echo "  sudo chmod -R 777 $PROJECT_ROOT/logs"
    echo ""
    echo "Or run this script with sudo:"
    echo "  sudo $0"
fi

echo ""
echo "Setup complete!"
echo ""
echo "You can now run: docker compose up -d"
