# Nubicustos Windows Setup Script
# Run this script in PowerShell as Administrator

param(
    [switch]$SkipDockerCheck
)

$ErrorActionPreference = "Stop"

Write-Host "Nubicustos Windows Setup" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Get script and project paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$EnvFile = Join-Path $ProjectRoot ".env"

# ============================================================================
# Docker Desktop Check
# ============================================================================
if (-not $SkipDockerCheck) {
    Write-Host "Checking Docker Desktop..." -ForegroundColor Yellow

    try {
        $dockerVersion = docker version --format '{{.Server.Version}}' 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Docker not responding"
        }
        Write-Host "Docker Desktop detected: $dockerVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Docker Desktop is not running or not installed." -ForegroundColor Red
        Write-Host "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
        Write-Host "After installation, ensure WSL 2 backend is enabled." -ForegroundColor Yellow
        exit 1
    }
}

# ============================================================================
# Directory Creation
# ============================================================================
Write-Host ""
Write-Host "Creating required directories..." -ForegroundColor Yellow

$directories = @(
    "credentials\aws",
    "credentials\azure",
    "credentials\gcp",
    "iac-staging",
    "iac-code",
    "kubeconfigs",
    "policies",
    "config\cloudmapper",
    "config\falco",
    "logs",
    "logs\nginx",
    "logs\postgresql",
    "logs\falco",
    "reports\prowler",
    "reports\prowler-azure",
    "reports\scoutsuite",
    "reports\cloudfox",
    "reports\cloudsploit",
    "reports\custodian",
    "reports\cloudmapper",
    "reports\pacu",
    "reports\enumerate-iam",
    "reports\kube-bench",
    "reports\kubescape",
    "reports\kube-hunter",
    "reports\trivy",
    "reports\grype",
    "reports\popeye",
    "reports\kube-linter",
    "reports\polaris",
    "reports\checkov",
    "reports\terrascan",
    "reports\tfsec",
    "reports\trufflehog",
    "reports\gitleaks",
    "reports\pmapper",
    "reports\cloudsplaining"
)

foreach ($dir in $directories) {
    $fullPath = Join-Path $ProjectRoot $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }
}
Write-Host "All directories created." -ForegroundColor Green

# ============================================================================
# Environment Configuration
# ============================================================================
Write-Host ""
Write-Host "Configuring environment..." -ForegroundColor Yellow

# Get the project path in a format Docker understands
# Convert backslashes to forward slashes for Docker
$ProjectPathForDocker = $ProjectRoot -replace '\\', '/'

# Check if .env exists
if (Test-Path $EnvFile) {
    $envContent = Get-Content $EnvFile -Raw

    # Check and update HOST_PROJECT_PATH
    if ($envContent -match "HOST_PROJECT_PATH=\s*$" -or $envContent -notmatch "HOST_PROJECT_PATH=") {
        if ($envContent -match "HOST_PROJECT_PATH=") {
            $envContent = $envContent -replace "HOST_PROJECT_PATH=.*", "HOST_PROJECT_PATH=$ProjectPathForDocker"
        } else {
            $envContent += "`nHOST_PROJECT_PATH=$ProjectPathForDocker"
        }
        Write-Host "Updated HOST_PROJECT_PATH in .env" -ForegroundColor Green
    }

    # Check and update HOST_REPORTS_PATH
    $ReportsPath = "$ProjectPathForDocker/reports"
    if ($envContent -match "HOST_REPORTS_PATH=\s*$" -or $envContent -notmatch "HOST_REPORTS_PATH=") {
        if ($envContent -match "HOST_REPORTS_PATH=") {
            $envContent = $envContent -replace "HOST_REPORTS_PATH=.*", "HOST_REPORTS_PATH=$ReportsPath"
        } else {
            $envContent += "`nHOST_REPORTS_PATH=$ReportsPath"
        }
        Write-Host "Updated HOST_REPORTS_PATH in .env" -ForegroundColor Green
    }

    Set-Content $EnvFile $envContent
} else {
    # Create .env from .env.example if it exists
    $EnvExample = Join-Path $ProjectRoot ".env.example"
    if (Test-Path $EnvExample) {
        Copy-Item $EnvExample $EnvFile
        $envContent = Get-Content $EnvFile -Raw
        $envContent = $envContent -replace "HOST_PROJECT_PATH=.*", "HOST_PROJECT_PATH=$ProjectPathForDocker"
        $envContent = $envContent -replace "HOST_REPORTS_PATH=.*", "HOST_REPORTS_PATH=$ProjectPathForDocker/reports"
        Set-Content $EnvFile $envContent
        Write-Host "Created .env from .env.example with Windows paths" -ForegroundColor Green
    } else {
        # Create minimal .env
        @"
# Nubicustos Environment Configuration (Windows)
HOST_PROJECT_PATH=$ProjectPathForDocker
HOST_REPORTS_PATH=$ProjectPathForDocker/reports
POSTGRES_PASSWORD=changeme
NEO4J_PASSWORD=cloudsecurity
"@ | Set-Content $EnvFile
        Write-Host "Created minimal .env file" -ForegroundColor Green
    }
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Project path configured: $ProjectPathForDocker" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review and update .env with your passwords" -ForegroundColor White
Write-Host "  2. docker compose up -d" -ForegroundColor White
Write-Host "  3. Open http://localhost:8080" -ForegroundColor White
Write-Host ""
Write-Host "If you encounter issues:" -ForegroundColor Yellow
Write-Host "  - Ensure Docker Desktop is running with WSL 2 backend" -ForegroundColor White
Write-Host "  - Check that the project is on a drive shared with Docker" -ForegroundColor White
Write-Host "  - Run: docker compose logs api" -ForegroundColor White
