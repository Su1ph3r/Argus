#!/bin/bash
# Setup script for Linux deployments of Nubicustos
# Fixes permission issues with credential storage, Docker socket access,
# and ensures all directories and scripts are properly configured.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/.env"

echo "Nubicustos Linux Permission Setup"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Running as root - will set all permissions"
else
    echo "Note: Some operations require sudo. Run with sudo for full setup."
    echo ""
fi

# ============================================================================
# SELinux Check
# ============================================================================
if command -v getenforce &> /dev/null; then
    SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Unknown")
    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
        echo "WARNING: SELinux is in Enforcing mode."
        echo "Docker volume mounts may fail. Consider running:"
        echo "  sudo chcon -Rt svirt_sandbox_file_t $PROJECT_ROOT"
        echo "Or set SELinux to Permissive: sudo setenforce 0"
        echo ""
    fi
fi

# ============================================================================
# Docker Socket Group Configuration
# ============================================================================
echo "Configuring Docker socket access..."

# Detect Docker socket group ID
if [ -S /var/run/docker.sock ]; then
    DOCKER_GID=$(stat -c '%g' /var/run/docker.sock 2>/dev/null || stat -f '%g' /var/run/docker.sock 2>/dev/null)
    echo "Detected Docker socket GID: $DOCKER_GID"

    # Update or create .env file with DOCKER_GID
    if [ -f "$ENV_FILE" ]; then
        if grep -q "^DOCKER_GID=" "$ENV_FILE"; then
            sed -i "s/^DOCKER_GID=.*/DOCKER_GID=$DOCKER_GID/" "$ENV_FILE" 2>/dev/null || \
            sed -i '' "s/^DOCKER_GID=.*/DOCKER_GID=$DOCKER_GID/" "$ENV_FILE"
            echo "Updated DOCKER_GID in .env"
        else
            echo "" >> "$ENV_FILE"
            echo "# Docker socket group ID for Linux (auto-detected)" >> "$ENV_FILE"
            echo "DOCKER_GID=$DOCKER_GID" >> "$ENV_FILE"
            echo "Added DOCKER_GID to .env"
        fi
    else
        echo "# Nubicustos Environment Configuration" > "$ENV_FILE"
        echo "" >> "$ENV_FILE"
        echo "# Docker socket group ID for Linux (auto-detected)" >> "$ENV_FILE"
        echo "DOCKER_GID=$DOCKER_GID" >> "$ENV_FILE"
        echo "Created .env with DOCKER_GID"
    fi
else
    echo "Warning: Docker socket not found at /var/run/docker.sock"
    echo "Make sure Docker is installed and running."
fi

# ============================================================================
# Directory Creation
# ============================================================================
echo ""
echo "Creating required directories..."

# Core directories
mkdir -p "$PROJECT_ROOT/credentials/aws"
mkdir -p "$PROJECT_ROOT/credentials/azure"
mkdir -p "$PROJECT_ROOT/credentials/gcp"
mkdir -p "$PROJECT_ROOT/iac-staging"
mkdir -p "$PROJECT_ROOT/iac-code"
mkdir -p "$PROJECT_ROOT/kubeconfigs"
mkdir -p "$PROJECT_ROOT/policies"
mkdir -p "$PROJECT_ROOT/config/cloudmapper"
mkdir -p "$PROJECT_ROOT/config/falco"

# Log directories
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/logs/nginx"
mkdir -p "$PROJECT_ROOT/logs/postgresql"
mkdir -p "$PROJECT_ROOT/logs/falco"

# Report directories (one per tool)
mkdir -p "$PROJECT_ROOT/reports/prowler"
mkdir -p "$PROJECT_ROOT/reports/prowler-azure"
mkdir -p "$PROJECT_ROOT/reports/scoutsuite"
mkdir -p "$PROJECT_ROOT/reports/cloudfox"
mkdir -p "$PROJECT_ROOT/reports/cloudsploit"
mkdir -p "$PROJECT_ROOT/reports/custodian"
mkdir -p "$PROJECT_ROOT/reports/cloudmapper"
mkdir -p "$PROJECT_ROOT/reports/pacu"
mkdir -p "$PROJECT_ROOT/reports/enumerate-iam"
mkdir -p "$PROJECT_ROOT/reports/kube-bench"
mkdir -p "$PROJECT_ROOT/reports/kubescape"
mkdir -p "$PROJECT_ROOT/reports/kube-hunter"
mkdir -p "$PROJECT_ROOT/reports/trivy"
mkdir -p "$PROJECT_ROOT/reports/grype"
mkdir -p "$PROJECT_ROOT/reports/popeye"
mkdir -p "$PROJECT_ROOT/reports/kube-linter"
mkdir -p "$PROJECT_ROOT/reports/polaris"
mkdir -p "$PROJECT_ROOT/reports/checkov"
mkdir -p "$PROJECT_ROOT/reports/terrascan"
mkdir -p "$PROJECT_ROOT/reports/tfsec"
mkdir -p "$PROJECT_ROOT/reports/trufflehog"
mkdir -p "$PROJECT_ROOT/reports/gitleaks"
mkdir -p "$PROJECT_ROOT/reports/pmapper"
mkdir -p "$PROJECT_ROOT/reports/cloudsplaining"

echo "All directories created."

# ============================================================================
# Script Permissions
# ============================================================================
echo ""
echo "Setting script execute permissions..."
chmod +x "$PROJECT_ROOT/scripts/"*.sh 2>/dev/null || true
echo "Script permissions set."

# ============================================================================
# Directory Permissions
# ============================================================================
echo ""
echo "Setting directory permissions..."

if [ "$EUID" -eq 0 ]; then
    # Credentials - API user (UID 1000) needs write access
    chown -R 1000:1000 "$PROJECT_ROOT/credentials"
    chmod -R 755 "$PROJECT_ROOT/credentials"

    # IaC staging - API user needs write access
    chown -R 1000:1000 "$PROJECT_ROOT/iac-staging"
    chmod -R 755 "$PROJECT_ROOT/iac-staging"

    # Reports - needs to be writable by multiple containers (various UIDs)
    # Use chmod 777 with sticky bit to ensure files are readable by all
    chmod -R 777 "$PROJECT_ROOT/reports"
    # Set default ACL to make new files world-readable (if ACL is supported)
    if command -v setfacl &> /dev/null; then
        setfacl -R -d -m o::rx "$PROJECT_ROOT/reports" 2>/dev/null || true
        echo "Set default ACL on reports directory"
    fi

    # Logs - needs to be writable by multiple containers
    chmod -R 777 "$PROJECT_ROOT/logs"

    # IaC code and kubeconfigs - read-only is fine, but ensure readable
    chmod -R 755 "$PROJECT_ROOT/iac-code"
    chmod -R 755 "$PROJECT_ROOT/kubeconfigs"
    chmod -R 755 "$PROJECT_ROOT/policies"
    chmod -R 755 "$PROJECT_ROOT/config"

    echo "Permissions set successfully."
else
    echo ""
    echo "Run with sudo to set all permissions, or run these commands:"
    echo ""
    echo "  sudo chown -R 1000:1000 $PROJECT_ROOT/credentials"
    echo "  sudo chown -R 1000:1000 $PROJECT_ROOT/iac-staging"
    echo "  sudo chmod -R 777 $PROJECT_ROOT/reports"
    echo "  sudo chmod -R 777 $PROJECT_ROOT/logs"
    echo ""
    echo "Or run: sudo $0"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "============================================"
echo "Setup complete!"
echo "============================================"
echo ""
if [ -n "$DOCKER_GID" ]; then
    echo "Docker GID configured: $DOCKER_GID"
fi
echo ""
echo "Next steps:"
echo "  1. docker compose up -d"
echo "  2. Open http://localhost:8080"
echo ""
echo "If you encounter permission issues:"
echo "  - Re-run this script with sudo"
echo "  - Ensure your user is in the docker group:"
echo "    sudo usermod -aG docker \$USER && newgrp docker"
echo ""
echo "If scans complete but show zero findings:"
echo "  - Re-run this script with sudo to fix report file permissions"
echo "  - Check API logs: docker logs security-api"
echo "  - Verify reports exist: ls -la ./reports/prowler/"
