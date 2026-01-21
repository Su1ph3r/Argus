#!/usr/bin/env python3
"""
Process and merge ScoutSuite and Prowler reports into a unified format
"""

import json
import logging
import os
import re
import shlex
import subprocess
from datetime import datetime
from pathlib import Path

import pandas as pd
import psycopg2
import psycopg2.extensions
from psycopg2.extras import Json

# Import remediation knowledge base
try:
    from remediation_kb import (
        get_default_description,
        get_default_remediation,
        get_poc_command,
        get_remediation,
    )
except ImportError:
    # Fallback if KB not available
    def get_remediation(ft, ci):
        return None

    def get_poc_command(ft, ci, ri=None):
        return None

    def get_default_remediation(s, d, cloud_provider="aws"):
        return "Review and remediate according to security best practices."

    def get_default_description(s, c, d, cloud_provider="aws"):
        return d or "Security finding detected."


def strip_html_tags(text: str | None) -> str | None:
    """Strip HTML tags from text while preserving content.

    Args:
        text: Input text that may contain HTML tags.

    Returns:
        Text with HTML tags removed and whitespace normalized,
        or the original value if input is None or not a string.
    """
    if not text or not isinstance(text, str):
        return text
    # Remove HTML tags but keep their content
    clean = re.sub(r'<[^>]+>', '', text)
    # Normalize whitespace
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean


# Import severity scoring module
try:
    from severity_scoring import calculate_risk_score, enrich_finding_with_scoring
except ImportError:
    # Fallback if scoring module not available
    def enrich_finding_with_scoring(finding):
        finding["risk_score"] = 50.0
        finding["cvss_score"] = 5.0
        finding["exploitation_likelihood"] = "likely"
        return finding

    def calculate_risk_score(finding, base_severity=None):
        return 50.0, "medium", {}


# Import attack validation modules (optional - graceful degradation if unavailable)
try:
    from blast_radius_analyzer import BlastRadiusAnalyzer
except ImportError:
    BlastRadiusAnalyzer = None

try:
    from poc_validator import PoCValidator
except ImportError:
    PoCValidator = None

try:
    from runtime_correlator import RuntimeCorrelator
except ImportError:
    RuntimeCorrelator = None


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ReportProcessor:
    # Generic resource names that should not be used as titles
    GENERIC_RESOURCE_NAMES = {
        "notconfigured",
        "not_configured",
        "unknown",
        "n/a",
        "na",
        "none",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "true",
        "false",
        "null",
        "undefined",
    }

    # AWS resource ID validation pattern
    AWS_RESOURCE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9\-\_:/.@]+$")

    # Service name normalization mapping (tool-specific -> KB normalized)
    SERVICE_NORMALIZATION = {
        # Prowler AWS resource types
        "awscloudtrailtrail": "cloudtrail",
        "awslambdafunction": "lambda",
        "awsec2securitygroup": "security-group",
        "awsec2instance": "ec2",
        "awsec2vpc": "vpc",
        "awss3bucket": "s3",
        "awsiamuser": "iam",
        "awsiamrole": "iam",
        "awsiampolicy": "iam",
        "awsrdsdbinstance": "rds",
        "awsebsvolume": "ebs",
        "awskmskey": "kms",
        "awssqsqueue": "sqs",
        "awssnssubscription": "sns",
        "awsaccount": "iam",
        # CloudSploit categories
        "cloudtrail": "cloudtrail",
        "ec2": "ec2",
        "s3": "s3",
        "iam": "iam",
        "rds": "rds",
        "lambda": "lambda",
        "vpc": "vpc",
        "kms": "kms",
        "sqs": "sqs",
        "sns": "sns",
        "ebs": "ebs",
        "elb": "elb",
        "configservice": "config",
        "securitygroup": "security-group",
        # ScoutSuite services (same mappings as CloudSploit - no duplicates needed)
    }

    # Check ID patterns to KB check mappings
    CHECK_ID_PATTERNS = {
        # CloudTrail checks
        r"cloudtrail.*enabled": "not-configured",
        r"cloudtrail.*multi.*region": "not-configured",
        r"cloudtrail.*log.*file.*validation": "no-log-validation",
        r"cloudtrail.*global": "no-global-services-logging",
        r"cloudtrail.*encrypted": "not-encrypted",
        # Security Group checks
        r"security.*group.*open": "opens-all-ports",
        r"security.*group.*ssh": "ssh-open",
        r"security.*group.*rdp": "rdp-open",
        r"default.*security.*group": "default-rules",
        # IAM checks
        r"password.*policy": "weak-password-policy",
        r"root.*account": "root-account-used",
        r"mfa": "no-mfa",
        r"access.*key.*rotation": "old-access-keys",
        # S3 checks
        r"bucket.*public": "public-access",
        r"bucket.*encrypt": "not-encrypted",
        r"bucket.*logging": "no-logging",
        r"bucket.*versioning": "no-versioning",
        # RDS checks
        r"rds.*public": "publicly-accessible",
        r"rds.*encrypt": "not-encrypted",
        r"rds.*backup": "no-backups",
        # EBS checks
        r"ebs.*encrypt": "not-encrypted",
        # Lambda checks
        r"lambda.*public": "public-access",
        r"lambda.*secret": "secrets-in-env",
        # KMS checks
        r"kms.*rotation": "no-rotation",
    }

    def __init__(self):
        # Require explicit password - no insecure defaults
        db_password = os.environ.get("DB_PASSWORD")
        if not db_password:
            logger.warning("DB_PASSWORD not set, using environment default")
            db_password = os.environ.get("POSTGRES_PASSWORD", "")

        self.db_config = {
            "host": os.environ.get("DB_HOST", "postgresql"),
            "database": os.environ.get("DB_NAME", "security_audits"),
            "user": os.environ.get("DB_USER", "auditor"),
            "password": db_password,
        }
        self.reports_dir = Path("/reports")
        self.processed_dir = Path("/processed")
        self.processed_dir.mkdir(exist_ok=True)
        # Store account_id discovered from any tool for cross-reference
        self._discovered_account_id = None

    def _is_generic_name(self, name):
        """Check if a name is generic/placeholder and shouldn't be used as title"""
        if not name:
            return True
        return name.lower().strip() in self.GENERIC_RESOURCE_NAMES

    def _normalize_service(self, resource_type):
        """Normalize resource type to KB service name."""
        if not resource_type:
            return "aws"
        # Clean and normalize the resource type
        normalized = resource_type.lower().replace(" ", "").replace("-", "").replace("_", "")
        return self.SERVICE_NORMALIZATION.get(normalized, resource_type.lower().replace(" ", "-"))

    def _normalize_check_id(self, check_id, title=""):
        """Normalize check ID to KB check name using pattern matching."""
        if not check_id:
            return ""
        # Combine check_id and title for better pattern matching
        combined = f"{check_id} {title}".lower()
        # Try each pattern
        for pattern, kb_key in self.CHECK_ID_PATTERNS.items():
            if re.search(pattern, combined, re.IGNORECASE):
                return kb_key
        # Return normalized check_id as fallback
        return check_id.lower().replace(" ", "-").replace("_", "-")

    def _generate_generic_poc_command(self, service, resource_id, finding):
        """Generate a generic AWS CLI verification command based on service type."""
        # Map services to appropriate AWS CLI describe commands
        service_commands = {
            "cloudtrail": "aws cloudtrail describe-trails --output json",
            "security-group": f"aws ec2 describe-security-groups --group-ids {resource_id} --output json"
            if resource_id and resource_id != "N/A"
            else "aws ec2 describe-security-groups --output json",
            "ec2": f"aws ec2 describe-instances --instance-ids {resource_id} --output json"
            if resource_id and "i-" in str(resource_id)
            else "aws ec2 describe-instances --output json",
            "s3": f'aws s3api get-bucket-policy --bucket {resource_id.split(":")[-1] if resource_id else "BUCKET"} --output json'
            if resource_id and resource_id != "N/A"
            else "aws s3 ls --output json",
            "iam": "aws iam get-account-password-policy --output json",
            "rds": f'aws rds describe-db-instances --db-instance-identifier {resource_id.split(":")[-1] if resource_id else ""} --output json'
            if resource_id and resource_id != "N/A"
            else "aws rds describe-db-instances --output json",
            "lambda": f'aws lambda get-function --function-name {resource_id.split(":")[-1] if resource_id else ""} --output json'
            if resource_id and resource_id != "N/A"
            else "aws lambda list-functions --output json",
            "kms": "aws kms list-keys --output json",
            "vpc": "aws ec2 describe-vpcs --output json",
            "ebs": "aws ec2 describe-volumes --output json",
            "sqs": "aws sqs list-queues --output json",
            "config": "aws configservice describe-configuration-recorders --output json",
        }

        # Get service-specific command or return None
        if service in service_commands:
            cmd = service_commands[service]
            # Validate resource_id before using
            if resource_id and resource_id != "N/A" and self._validate_resource_id(resource_id):
                return cmd
            # Use the base command without specific resource ID
            base_cmd = service_commands[service]
            # Remove resource-specific parts for generic verification
            if "--group-ids" in base_cmd or "--instance-ids" in base_cmd or "--bucket" in base_cmd:
                return service_commands.get(service, "").split("--")[0].strip() + " --output json"
            return base_cmd

        return None

    def _generate_azure_poc_command(self, service, resource_id, finding):
        """Generate an Azure CLI verification command based on service type."""
        # Map services to appropriate Azure CLI commands
        service_commands = {
            "storageaccounts": "az storage account list --output json",
            "storage": "az storage account list --output json",
            "virtualmachines": "az vm list --output json",
            "vm": "az vm list --output json",
            "sqldatabases": "az sql db list --output json",
            "sql": "az sql server list --output json",
            "keyvault": "az keyvault list --output json",
            "appservice": "az webapp list --output json",
            "webapp": "az webapp list --output json",
            "networkinterfaces": "az network nic list --output json",
            "nic": "az network nic list --output json",
            "securitygroups": "az network nsg list --output json",
            "nsg": "az network nsg list --output json",
            "virtualnetworks": "az network vnet list --output json",
            "vnet": "az network vnet list --output json",
            "loadbalancers": "az network lb list --output json",
            "lb": "az network lb list --output json",
            "applicationgateways": "az network application-gateway list --output json",
            "appgateway": "az network application-gateway list --output json",
            "cosmosdb": "az cosmosdb list --output json",
            "aks": "az aks list --output json",
            "kubernetes": "az aks list --output json",
            "acr": "az acr list --output json",
            "containerregistry": "az acr list --output json",
            "monitor": "az monitor activity-log list --output json",
            "activitylog": "az monitor activity-log list --output json",
            "defender": "az security pricing list --output json",
            "securitycenter": "az security pricing list --output json",
            "rbac": "az role assignment list --output json",
            "iam": "az role assignment list --output json",
            "policy": "az policy assignment list --output json",
            "resourcegroups": "az group list --output json",
            "rg": "az group list --output json",
            "subscriptions": "az account list --output json",
            "subscription": "az account list --output json",
            "logging": "az monitor diagnostic-settings list --output json",
            "diagnostics": "az monitor diagnostic-settings list --output json",
            # Additional Azure services
            "appinsights": "az monitor app-insights component list --output json",
            "applicationinsights": "az monitor app-insights component list --output json",
            "insights": "az monitor app-insights component list --output json",
            "network": "az network nsg list --output json",
            "security": "az security pricing list --output json",
            "alert": "az monitor activity-log alert list --output json",
            "activitylogalert": "az monitor activity-log alert list --output json",
            "logalert": "az monitor activity-log alert list --output json",
            "contact": "az security contact list --output json",
            "securitycontact": "az security contact list --output json",
            "autoprovisioning": "az security auto-provisioning-setting list --output json",
            "provisioning": "az security auto-provisioning-setting list --output json",
            "disk": "az disk list --output json",
            "disks": "az disk list --output json",
            "manageddisk": "az disk list --output json",
            "manageddisks": "az disk list --output json",
            "functionapp": "az functionapp list --output json",
            "function": "az functionapp list --output json",
            "functions": "az functionapp list --output json",
            "logicapp": "az logic workflow list --output json",
            "logic": "az logic workflow list --output json",
            "redis": "az redis list --output json",
            "cache": "az redis list --output json",
            "servicebus": "az servicebus namespace list --output json",
            "eventhub": "az eventhubs namespace list --output json",
            "postgresql": "az postgres server list --output json",
            "postgres": "az postgres server list --output json",
            "mysql": "az mysql server list --output json",
            "mariadb": "az mariadb server list --output json",
        }

        # Normalize service name
        normalized_service = service.lower().replace("-", "").replace("_", "")

        # Get service-specific command
        if normalized_service in service_commands:
            return service_commands[normalized_service]

        # Try partial matches
        for key, cmd in service_commands.items():
            if key in normalized_service or normalized_service in key:
                return cmd

        return None

    def _validate_resource_id(self, resource_id: str | None) -> bool:
        """Validate that a resource ID matches expected AWS patterns.

        Args:
            resource_id: The AWS resource ID to validate.

        Returns:
            True if the resource ID matches AWS naming patterns, False otherwise.

        Note:
            This prevents command injection by ensuring resource IDs only
            contain safe characters: alphanumeric, hyphens, underscores,
            colons, slashes, periods, and @ symbols.
        """
        if not resource_id:
            return False
        # Must match safe AWS resource ID pattern
        return bool(self.AWS_RESOURCE_ID_PATTERN.match(resource_id))

    def _validate_azure_resource_id(self, resource_id: str | None) -> bool:
        """Validate that a resource ID matches expected Azure patterns.

        Args:
            resource_id: The Azure resource ID to validate.

        Returns:
            True if the resource ID matches Azure naming patterns, False otherwise.

        Note:
            Azure resource IDs typically start with /subscriptions/ or are simple names.
            Allowed characters: alphanumeric, hyphens, underscores, forward slashes, dots.
        """
        if not resource_id:
            return False
        # Azure resource IDs typically start with /subscriptions/ or are simple names
        # Allow alphanumeric, hyphens, underscores, forward slashes, and dots
        azure_pattern = re.compile(r"^[a-zA-Z0-9\-_/\.]+$")
        return bool(azure_pattern.match(resource_id))

    def _run_cli_command(
        self, command: str | list[str], cli_name: str, timeout: int = 30
    ) -> str:
        """Run a CLI command safely and return the output.

        This is the shared implementation for AWS and Azure CLI execution.
        Uses shlex for safe command parsing to prevent command injection.

        Args:
            command: Command string or list of command parts to execute.
            cli_name: The CLI executable name to validate ('aws' or 'az').
            timeout: Command timeout in seconds (default: 30).

        Returns:
            Command output on success, or an error message string on failure.

        Security:
            - Uses shlex.split() for safe command parsing
            - Validates command starts with expected CLI binary
            - Uses shell=False to prevent shell injection
        """
        try:
            # Parse command safely using shlex to prevent command injection
            if isinstance(command, str):
                parts = shlex.split(command)
            else:
                parts = list(command)

            # Validate command starts with expected CLI
            if not parts or parts[0] != cli_name:
                logger.warning(f"Invalid {cli_name} CLI command attempted")
                return "Invalid command format"

            # Execute with shell=False (explicit for security)
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # Explicit: never use shell=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                # Log full error but return sanitized message
                logger.debug(f"{cli_name} CLI command failed: {result.stderr.strip()}")
                return "Command execution failed"
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except FileNotFoundError:
            return f"{cli_name.upper()} CLI not available"
        except (ValueError, OSError) as e:
            # ValueError: shlex parsing errors
            # OSError: process creation errors
            logger.error(f"Error running {cli_name} CLI: {str(e)}")
            return "Command execution error"

    def _run_aws_cli(self, command: str | list[str]) -> str:
        """Run an AWS CLI command safely and return the output.

        Args:
            command: AWS CLI command string or list of command parts.

        Returns:
            Command output on success, or an error message string on failure.

        Security:
            Uses shlex for safe command parsing to prevent injection.
        """
        return self._run_cli_command(command, "aws")

    def _run_azure_cli(self, command: str | list[str]) -> str:
        """Run an Azure CLI command safely and return the output.

        Args:
            command: Azure CLI command string or list of command parts.

        Returns:
            Command output on success, or an error message string on failure.

        Security:
            Uses shlex for safe command parsing to prevent injection.
        """
        return self._run_cli_command(command, "az")

    def _enhance_finding(self, finding, service, check_id, cloud_provider="aws"):
        """Enhance a finding with data from remediation KB.

        This method normalizes service/check_id to match KB entries and:
        1. Adds description if missing
        2. Adds remediation guidance if missing
        3. Generates and runs PoC verification commands
        4. Captures command output for display
        """
        # Normalize service and check_id to match KB keys
        normalized_service = self._normalize_service(service)
        title = finding.get("check_title", finding.get("title", ""))
        normalized_check = self._normalize_check_id(check_id, title)

        # Try to get KB data with normalized values, fallback to original
        kb_data = get_remediation(normalized_service, normalized_check)
        if not kb_data:
            kb_data = get_remediation(service.lower(), check_id.lower())
        if not kb_data:
            kb_data = get_remediation(normalized_service, check_id.lower())

        # Enhance description if empty or generic
        current_desc = finding.get("description", "")
        if not current_desc or len(current_desc) < 30 or "no description" in current_desc.lower():
            if kb_data and kb_data.get("description"):
                finding["description"] = kb_data["description"]
            else:
                finding["description"] = get_default_description(
                    normalized_service, check_id, current_desc, cloud_provider
                )

        # Add remediation if empty or just contains a status message
        current_remediation = finding.get("remediation", "")
        is_status_message = current_remediation and any(
            x in current_remediation.lower()
            for x in [
                "is not",
                "not enabled",
                "not configured",
                "has default",
                "is publicly",
                "no cloudtrail",
            ]
        )
        if not current_remediation or current_remediation == "N/A" or is_status_message:
            if kb_data and kb_data.get("remediation"):
                finding["remediation"] = kb_data["remediation"]
            else:
                finding["remediation"] = get_default_remediation(
                    normalized_service, finding.get("description", ""), cloud_provider
                )

        # Generate PoC command for verification reference
        resource_id = finding.get("resource_id", "")
        poc_command = get_poc_command(normalized_service, normalized_check, resource_id)
        if not poc_command:
            poc_command = get_poc_command(service.lower(), check_id.lower(), resource_id)
        if not poc_command:
            # Generate a generic verification command based on service and cloud provider
            if cloud_provider == "azure":
                poc_command = self._generate_azure_poc_command(
                    normalized_service, resource_id, finding
                )
            else:
                poc_command = self._generate_generic_poc_command(
                    normalized_service, resource_id, finding
                )

        # Set poc_verification to ONLY the CLI command (for user to run)
        # poc_evidence should contain scanner output (set by parser)
        if poc_command:
            finding["poc_verification"] = poc_command

            # Update remediation_code with the CLI command
            current_remediation_code = finding.get("remediation_code", {})
            if not isinstance(current_remediation_code, dict):
                current_remediation_code = {}
            cli_key = f"{cloud_provider}_cli"
            if cli_key not in current_remediation_code:
                current_remediation_code[cli_key] = poc_command
                finding["remediation_code"] = current_remediation_code

        # Ensure affected_resources is populated
        if not finding.get("affected_resources") or len(finding.get("affected_resources", [])) == 0:
            # Create at least one affected resource from the finding data
            affected_resources = []
            if finding.get("resource_id"):
                affected_resources.append(
                    {
                        "id": finding.get("resource_id", ""),
                        "name": finding.get("resource_name", finding.get("resource_id", "")),
                        "region": finding.get("region", "global"),
                        "type": finding.get("resource_type", service),
                    }
                )
            finding["affected_resources"] = affected_resources
            finding["affected_count"] = len(affected_resources)

        return finding

    def _build_meaningful_title(self, service, finding_id, description, resource_name):
        """Build a meaningful title from available data"""
        # If description exists and is meaningful, use it
        if description and len(description) > 10 and not self._is_generic_name(description):
            return description

        # Build title from finding_id (e.g., "cloudtrail-encryption-disabled" -> "CloudTrail Encryption Disabled")
        title = finding_id.replace("-", " ").replace("_", " ").title()

        # Prepend service name if not already in title
        service_name = service.replace("-", " ").replace("_", " ").title()
        if service_name.lower() not in title.lower():
            title = f"{service_name}: {title}"

        return title

    def _generate_canonical_id(self, finding):
        """Generate a canonical ID for grouping similar findings across tools.

        The canonical ID normalizes: resource_type + normalized_check + account_id
        This groups findings that are essentially the same issue across different tools.
        """
        import hashlib
        import re

        # Normalize the check_id by removing tool-specific prefixes/suffixes
        check_id = finding.get("check_id", finding.get("type", "unknown"))
        # Remove common prefixes like 'prowler_', 'scoutsuite_', etc.
        normalized_check = re.sub(
            r"^(prowler_|scoutsuite_|cloudsploit_|polaris_|kube_linter_)",
            "",
            check_id.lower(),
        )
        # Replace separators with underscores
        normalized_check = re.sub(r"[-.\s]+", "_", normalized_check)

        # Get components for canonical ID
        resource_type = finding.get("resource_type", "unknown").lower()
        account_id = finding.get("account_id", "unknown")
        region = finding.get("region", "global").lower()

        # Create canonical ID: resource_type + check + account + region
        canonical_parts = [resource_type, normalized_check, account_id, region]
        canonical_str = "_".join(part for part in canonical_parts if part)

        # Use hash for very long IDs
        if len(canonical_str) > 200:
            return hashlib.md5(canonical_str.encode()).hexdigest()

        return canonical_str

    def connect_db(self) -> psycopg2.extensions.connection | None:
        """Connect to PostgreSQL database.

        Returns:
            PostgreSQL connection object, or None if connection fails.

        Note:
            Connection failures are logged but not raised, allowing
            callers to handle missing connections gracefully.
        """
        try:
            return psycopg2.connect(**self.db_config)
        except psycopg2.OperationalError as e:
            logger.error(f"Database connection failed (operational error): {e}")
            return None
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            return None

    def process_scoutsuite_report(self, report_path):
        """Process ScoutSuite report (JavaScript or JSON format)

        Creates ONE finding per finding_id with all affected resources stored in affected_resources.
        """
        logger.info(f"Processing ScoutSuite report: {report_path}")

        findings = []
        try:
            with open(report_path, encoding="utf-8") as f:
                content = f.read()

            # Handle JavaScript format: strip 'scoutsuite_results = ' prefix
            js_prefix_patterns = ["scoutsuite_results =\n", "scoutsuite_results = "]
            json_content = content.strip()

            for prefix in js_prefix_patterns:
                if json_content.startswith(prefix):
                    json_content = json_content[len(prefix) :]
                    break

            # Remove trailing semicolon if present
            if json_content.rstrip().endswith(";"):
                json_content = json_content.rstrip()[:-1]

            data = json.loads(json_content)

            # Extract account_id from aws_account_id (ScoutSuite specific) or account_id
            account_id = data.get("aws_account_id", data.get("account_id", "unknown"))
            if account_id and account_id != "unknown":
                self._discovered_account_id = account_id

            # Normalize cloud provider name to lowercase standard format
            raw_provider = data.get("provider_name", data.get("provider", "aws"))
            provider_map = {
                "amazon web services": "aws",
                "aws": "aws",
                "azure": "azure",
                "microsoft azure": "azure",
                "google cloud platform": "gcp",
                "gcp": "gcp",
            }
            normalized_provider = provider_map.get(raw_provider.lower(), raw_provider.lower())

            metadata = {
                "tool": "scoutsuite",
                "cloud_provider": normalized_provider,
                "scan_date": datetime.now().isoformat(),
                "account_id": account_id,
            }

            # Map ScoutSuite severity levels to standard severity
            severity_map = {
                "danger": "high",  # danger = high (not critical, as ScoutSuite uses it broadly)
                "warning": "medium",
                "info": "low",
            }

            # Store full services data for resource lookup
            all_services = data.get("services", {})

            # Extract findings from nested structure: services.[service].findings.[finding_id]
            for service, service_data in all_services.items():
                if not isinstance(service_data, dict):
                    continue

                for finding_id, finding_data in service_data.get("findings", {}).items():
                    if not isinstance(finding_data, dict):
                        continue

                    # Only process findings that have flagged items
                    flagged_count = finding_data.get("flagged_items", 0)
                    if flagged_count == 0:
                        continue

                    # Get severity level and map it
                    raw_severity = finding_data.get("level", "warning")
                    severity = severity_map.get(raw_severity.lower(), "medium")

                    # Items array contains ALL affected resources for this finding type
                    items = finding_data.get("items", [])

                    # Get the finding description and rationale, stripping HTML tags
                    finding_description = strip_html_tags(finding_data.get("description", ""))
                    finding_rationale = strip_html_tags(finding_data.get("rationale", ""))
                    finding_remediation = strip_html_tags(finding_data.get("remediation", ""))

                    # Build a meaningful title from finding_id
                    # e.g., "cloudtrail-not-configured" -> "CloudTrail Not Configured"
                    title_parts = finding_id.replace("-", " ").replace("_", " ").split()
                    check_title = " ".join(word.capitalize() for word in title_parts)

                    # Parse all items to build affected_resources array with full resource data
                    affected_resources = []
                    regions_seen = set()
                    resource_configs = []  # Store actual resource configurations

                    for item in items:
                        resource_info = self._parse_scoutsuite_item(item, service, all_services)
                        affected_resources.append(resource_info)
                        if resource_info.get("region"):
                            regions_seen.add(resource_info["region"])
                        # Collect resource configuration for PoC evidence
                        if resource_info.get("configuration"):
                            resource_configs.append(
                                {
                                    "id": resource_info.get("id"),
                                    "name": resource_info.get("name"),
                                    "config": resource_info.get("configuration"),
                                }
                            )

                    # Determine primary region - use most common or 'global' if mixed
                    if len(regions_seen) == 1:
                        primary_region = list(regions_seen)[0]
                    elif len(regions_seen) > 1:
                        primary_region = "multiple"
                    else:
                        primary_region = "global"

                    # Create ONE finding per finding_id with all affected resources
                    # Build a better resource name - summarize affected resources
                    if len(affected_resources) == 1:
                        resource_name = affected_resources[0].get(
                            "name", affected_resources[0].get("id", check_title)
                        )
                    elif len(affected_resources) > 1:
                        resource_name = f"{len(affected_resources)} {service} resources"
                    else:
                        resource_name = check_title

                    # Build proof of concept evidence from scanner output
                    evidence_parts = []
                    if resource_configs:
                        evidence_parts.append(
                            f"Found {len(resource_configs)} affected resource(s)"
                        )
                        evidence_parts.append("\nResource Configuration(s):")
                        for rc in resource_configs[:5]:  # Limit to 5 for readability
                            config_json = json.dumps(rc.get("config", {}), indent=2)
                            if len(config_json) > 1500:
                                config_json = config_json[:1500] + "\n  ... (truncated)"
                            evidence_parts.append(
                                f"\n{rc.get('name', rc.get('id', 'Unknown'))}:"
                            )
                            evidence_parts.append(config_json)
                        if len(resource_configs) > 5:
                            evidence_parts.append(
                                f"\n... and {len(resource_configs) - 5} more resource(s)"
                            )

                    poc_evidence_text = (
                        "\n".join(evidence_parts) if evidence_parts else ""
                    )

                    finding = {
                        "service": service,
                        "type": finding_id,
                        "check_id": f"scoutsuite_{finding_id}",
                        "check_title": check_title,
                        "severity": severity,
                        "status": "fail",
                        "resource_id": finding_id,  # Use finding_id as the unique resource identifier
                        "resource_type": service,
                        "resource_name": resource_name,
                        "region": primary_region,
                        "account_id": account_id,
                        "description": finding_rationale if finding_rationale else check_title,
                        "remediation": finding_remediation,
                        "compliance": finding_data.get("compliance", []),
                        "checked_items": finding_data.get("checked_items", 0),
                        "flagged_items": flagged_count,
                        "affected_resources": affected_resources,
                        "affected_count": len(affected_resources),
                        "poc_verification": "",  # Will be set to CLI command by _enhance_finding
                        "poc_evidence": poc_evidence_text,
                    }
                    # Enhance finding with KB data and cloud provider context
                    finding = self._enhance_finding(finding, service, finding_id, normalized_provider)
                    findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from ScoutSuite")
            return metadata, findings

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error in ScoutSuite report: {e}")
            return None, []
        except Exception as e:
            logger.error(f"Error processing ScoutSuite report: {e}")
            import traceback

            traceback.print_exc()
            return None, []

    def _parse_scoutsuite_item(self, item, service, all_services=None):
        """Parse a ScoutSuite item path into resource details with actual configuration lookup."""
        if isinstance(item, str):
            # Parse path like "cloudtrail.regions.ap-northeast-1.NotConfigured" (AWS)
            # or "iam.policies.ANPAI7XKCFMBPM3QQRRVQ.PolicyDocument.Statement.0" (AWS)
            # or "keyvault.subscriptions.SUB_ID.vaults.scoutid-XXX.property" (Azure)
            parts = item.split(".")

            # Extract region from path (AWS uses 'regions', Azure uses 'location' in data)
            region = "global"
            for i, part in enumerate(parts):
                if part == "regions" and i + 1 < len(parts):
                    region = parts[i + 1]
                    break

            # Extract meaningful resource identifiers from path
            resource_id = item
            resource_name = None
            resource_type = service
            configuration = None

            # Try to look up actual resource data from services
            if all_services and len(parts) >= 3:
                try:
                    # Navigate path: service.collection.resource_id...
                    service_name = parts[0]
                    service_data = all_services.get(service_name, {})

                    # Collection candidates for both AWS and Azure
                    # AWS: policies, roles, users, buckets, vpcs, security_groups, instances, etc.
                    # Azure: vaults, storage_accounts, security_groups, instances, servers, etc.
                    collection_candidates = [
                        # AWS collections
                        "policies",
                        "roles",
                        "users",
                        "groups",
                        "buckets",
                        "vpcs",
                        "security_groups",
                        "instances",
                        "volumes",
                        "trails",
                        "queues",
                        "topics",
                        "keys",
                        "functions",
                        # Azure collections
                        "vaults",
                        "storage_accounts",
                        "servers",
                        "databases",
                        "web_apps",
                        "disks",
                        "images",
                        "snapshots",
                        "caches",
                        "diagnostic_settings",
                        "log_alerts",
                        "log_profiles",
                        "resources_logging",
                        "network_interfaces",
                        "public_ip_addresses",
                        "virtual_networks",
                        "subnets",
                        "application_gateways",
                        "load_balancers",
                        "role_assignments",
                        "role_definitions",
                        "pricings",
                        "auto_provisioning_settings",
                        "security_contacts",
                        "information_protection_policies",
                    ]

                    # Handle Azure subscriptions path: service.subscriptions.SUB_ID.collection.resource
                    # Azure paths can be deeply nested: security_groups.scoutid-xxx.security_rules.RULE_ID
                    if "subscriptions" in parts:
                        sub_idx = parts.index("subscriptions")
                        if sub_idx + 1 < len(parts):
                            sub_id = parts[sub_idx + 1]
                            subscriptions_data = service_data.get("subscriptions", {})
                            sub_data = subscriptions_data.get(sub_id, {})

                            # Navigate through nested collections in Azure paths
                            # Start from subscription data and traverse the path
                            current_data = sub_data
                            remaining_parts = parts[sub_idx + 2:]  # Parts after SUB_ID

                            i = 0
                            while i < len(remaining_parts):
                                part = remaining_parts[i]

                                if part in collection_candidates and isinstance(current_data, dict):
                                    # This is a collection - get the collection dict
                                    collection = current_data.get(part, {})

                                    # Next part should be the resource key
                                    if i + 1 < len(remaining_parts) and isinstance(collection, dict):
                                        resource_key = remaining_parts[i + 1]
                                        next_data = collection.get(resource_key)

                                        if next_data and isinstance(next_data, dict):
                                            # Found resource data - this might be final or intermediate
                                            configuration = next_data
                                            resource_name = next_data.get(
                                                "name", next_data.get("Name", resource_key)
                                            )
                                            resource_id = next_data.get(
                                                "id", next_data.get("arn", resource_key)
                                            )
                                            # Azure resources have location instead of region
                                            if next_data.get("location"):
                                                region = next_data["location"]

                                            # Continue deeper if there are more nested collections
                                            current_data = next_data
                                            i += 2  # Move past collection and resource key
                                            continue

                                i += 1
                    else:
                        # AWS path handling
                        for i, part in enumerate(parts[1:], 1):
                            if part in collection_candidates and i + 1 < len(parts):
                                collection = service_data.get(part, {})
                                resource_key = parts[i + 1]
                                # Handle regions in path: service.regions.region.collection.resource_id
                                if part == "regions" and i + 2 < len(parts):
                                    region_data = collection.get(parts[i + 1], {})
                                    if i + 3 < len(parts) and parts[i + 2] in collection_candidates:
                                        collection = region_data.get(parts[i + 2], {})
                                        resource_key = parts[i + 3] if i + 3 < len(parts) else None

                                if resource_key and isinstance(collection, dict):
                                    resource_data = collection.get(resource_key)
                                    if resource_data and isinstance(resource_data, dict):
                                        configuration = resource_data
                                        resource_name = resource_data.get(
                                            "name", resource_data.get("Name", resource_key)
                                        )
                                        resource_id = resource_data.get(
                                            "id", resource_data.get("arn", resource_key)
                                        )
                                        break
                except Exception:
                    # Silently fail resource lookup, continue with path-based extraction
                    pass

            # Fallback: Extract identifiers from path patterns
            for i, part in enumerate(parts):
                # AWS resource ID patterns
                if part.startswith("vpc-"):
                    resource_id = part
                    resource_type = "vpc"
                elif part.startswith("sg-"):
                    resource_id = part
                    resource_type = "security_group"
                elif part.startswith("vol-"):
                    resource_id = part
                    resource_type = "volume"
                elif part.startswith("acl-"):
                    resource_id = part
                    resource_type = "network_acl"
                elif part.startswith("i-"):
                    resource_id = part
                    resource_type = "instance"
                elif part.startswith("arn:"):
                    resource_id = part
                elif part.startswith("ANPA") or part.startswith("AROA") or part.startswith("AIDA"):
                    # IAM resource IDs
                    resource_id = part
                    resource_type = "iam"
                # Azure resource ID patterns
                elif part.startswith("scoutid-"):
                    # ScoutSuite-generated Azure resource ID
                    resource_id = part
                elif part.startswith("/subscriptions/"):
                    # Full Azure resource path
                    resource_id = part
                # Check for named resources (both AWS and Azure collections)
                elif i > 0 and parts[i - 1] in [
                    # AWS
                    "buckets",
                    "queues",
                    "topics",
                    "roles",
                    "users",
                    "policies",
                    # Azure
                    "vaults",
                    "storage_accounts",
                    "servers",
                    "web_apps",
                    "security_groups",
                    "virtual_networks",
                    "network_interfaces",
                ]:
                    if resource_name is None:
                        resource_name = part
                        resource_id = part

            result = {
                "id": resource_id,
                "name": resource_name or resource_id,
                "region": region,
                "type": resource_type,
                "path": item,
            }
            if configuration:
                result["configuration"] = configuration
            return result
        elif isinstance(item, dict):
            return {
                "id": item.get("id", item.get("name", str(item))),
                "name": item.get("name", item.get("id", "")),
                "region": item.get("region", "global"),
                "type": item.get("type", service),
                "configuration": item,
            }
        else:
            return {
                "id": str(item),
                "name": str(item),
                "region": "global",
                "type": service,
            }

    def process_prowler_report(self, report_path):
        """Process Prowler JSON report (supports both OCSF and legacy formats)"""
        logger.info(f"Processing Prowler report: {report_path}")

        findings = []
        detected_provider = None  # Will be extracted from report data

        # Pre-detect cloud provider from report path for use during processing
        report_path_str = str(report_path)
        path_detected_provider = "aws"  # Default
        if "prowler-azure" in report_path_str or "/azure/" in report_path_str:
            path_detected_provider = "azure"
        elif "prowler-gcp" in report_path_str or "/gcp/" in report_path_str:
            path_detected_provider = "gcp"

        try:
            with open(report_path) as f:
                content = f.read()

            # Determine format: OCSF (array) or legacy (newline-delimited JSON)
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    # OCSF format - array of findings
                    for finding_data in data:
                        # Extract cloud provider from first finding if not yet detected
                        if detected_provider is None:
                            cloud_data = finding_data.get("cloud", {})
                            detected_provider = cloud_data.get("provider", "").lower() or path_detected_provider
                        finding = self._parse_prowler_ocsf(finding_data)
                        if finding:
                            # Enhance finding with KB data and cloud provider context
                            service = finding.get("resource_type", "aws")
                            check_id = finding.get("check_id", "")
                            provider = detected_provider or path_detected_provider
                            finding = self._enhance_finding(finding, service, check_id, provider)
                            findings.append(finding)
                else:
                    # Single object - treat as legacy
                    finding = self._parse_prowler_legacy(data, path_detected_provider)
                    if finding:
                        service = finding.get("resource_type", "aws")
                        check_id = finding.get("check_id", "")
                        finding = self._enhance_finding(finding, service, check_id, path_detected_provider)
                        findings.append(finding)
            except json.JSONDecodeError:
                # Try newline-delimited JSON (legacy format)
                for line in content.split("\n"):
                    if line.strip():
                        try:
                            finding_data = json.loads(line)
                            finding = self._parse_prowler_legacy(finding_data, path_detected_provider)
                            if finding:
                                service = finding.get("resource_type", "aws")
                                check_id = finding.get("check_id", "")
                                finding = self._enhance_finding(finding, service, check_id, path_detected_provider)
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            # Final cloud provider: prefer detected from data, fallback to path detection
            if not detected_provider:
                detected_provider = path_detected_provider

            metadata = {
                "tool": "prowler",
                "cloud_provider": detected_provider,
                "scan_date": datetime.now().isoformat(),
            }

            logger.info(f"Extracted {len(findings)} findings from Prowler")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing Prowler report: {e}")
            return None, []

    def _parse_prowler_ocsf(self, finding_data):
        """Parse Prowler OCSF format finding"""
        try:
            metadata = finding_data.get("metadata", {})
            check_id = metadata.get("event_code", "")
            unmapped = finding_data.get("unmapped", {})
            remediation_data = unmapped.get("remediation", {})
            compliance_data = unmapped.get("compliance", {})

            # Extract account_id and cloud provider from cloud object
            cloud_data = finding_data.get("cloud", {})
            account_data = cloud_data.get("account", {})
            account_id = account_data.get("uid", "")
            if account_id and account_id != "":
                self._discovered_account_id = account_id

            # Get cloud provider for correct CLI key naming
            finding_cloud_provider = cloud_data.get("provider", "aws").lower()

            # Map OCSF severity_id to text (1=Info, 2=Low, 3=Medium, 4=High, 5=Critical)
            severity_map = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
            severity = severity_map.get(finding_data.get("severity_id", 3), "medium")

            # Get resource info
            resources = finding_data.get("resources", [{}])
            resource = resources[0] if resources else {}

            # Build remediation commands
            remediation_commands = []
            cli_cmd = remediation_data.get("cli", "") or remediation_data.get("CLI", "")

            # Determine CLI key based on cloud provider
            cli_key = f"{finding_cloud_provider}_cli"  # aws_cli, azure_cli, gcp_cli
            cli_description = f"{finding_cloud_provider.upper()} CLI remediation command"
            if finding_cloud_provider == "azure":
                cli_description = "Azure CLI remediation command"
            elif finding_cloud_provider == "gcp":
                cli_description = "Google Cloud CLI remediation command"
            else:
                cli_description = "AWS CLI remediation command"

            if cli_cmd:
                remediation_commands.append(
                    {
                        "type": "cli",
                        "command": cli_cmd,
                        "description": cli_description,
                    }
                )

            # Build remediation code with provider-specific key
            remediation_code = {}
            iac = remediation_data.get("terraform", "") or remediation_data.get("NativeIaC", "")
            if iac:
                remediation_code["terraform"] = iac
            if cli_cmd:
                remediation_code[cli_key] = cli_cmd

            # Build remediation resources
            remediation_resources = []
            related_url = unmapped.get("related_url", "")
            doc_title = "AWS Documentation"
            if finding_cloud_provider == "azure":
                doc_title = "Azure Documentation"
            elif finding_cloud_provider == "gcp":
                doc_title = "Google Cloud Documentation"
            if related_url:
                remediation_resources.append(
                    {
                        "title": doc_title,
                        "url": related_url,
                        "type": "documentation",
                    }
                )

            # Get proper title from finding_info.title (OCSF standard location)
            finding_info = finding_data.get("finding_info", {})
            proper_title = (
                finding_info.get("title", "")
                or finding_data.get("activity_name", "")
                or check_id.replace("_", " ").title()
            )

            # Get proper description from finding_info.desc
            proper_description = (
                finding_info.get("desc", "")
                or finding_data.get("status_detail", "")
                or finding_data.get("message", "")
            )

            # Extract actual resource configuration as evidence (this IS the proof)
            resource_data = resource.get("data", {})
            resource_metadata = resource_data.get("metadata", {})

            # Build comprehensive evidence object
            evidence_obj = {
                "check_id": check_id,
                "message": finding_data.get("message", ""),
                "status_detail": finding_data.get("status_detail", ""),
                "severity": finding_data.get("severity", ""),
                "risk": unmapped.get("risk", ""),
            }

            # Add resource configuration as proof (this is the actual evidence)
            if resource_metadata:
                evidence_obj["resource_configuration"] = resource_metadata
            elif resource_data:
                evidence_obj["resource_data"] = resource_data

            # Build proof of concept evidence from scanner output
            evidence_parts = []
            status_detail = finding_data.get("status_detail", "")
            message = finding_data.get("message", "")

            if status_detail or message or resource_metadata:
                if message:
                    evidence_parts.append(f"Finding: {message}")
                if status_detail and status_detail != message:
                    evidence_parts.append(f"Detail: {status_detail}")
                if resource_metadata:
                    # Format key evidence from resource configuration
                    config_preview = json.dumps(resource_metadata, indent=2)
                    if len(config_preview) > 1500:
                        config_preview = config_preview[:1500] + "\n  ... (truncated)"
                    evidence_parts.append(f"\nResource Configuration:\n{config_preview}")

            poc_evidence_text = "\n".join(evidence_parts) if evidence_parts else json.dumps(evidence_obj, indent=2)

            return {
                "check_id": check_id,
                "check_title": proper_title,
                "severity": severity,
                "status": "open" if finding_data.get("status_code", "FAIL") != "PASS" else "closed",
                "region": resource.get("region", cloud_data.get("region", "global")),
                "resource_id": resource.get("uid", ""),
                "resource_type": resource.get("type", ""),
                "resource_name": resource.get("name", resource.get("uid", "")),
                "account_id": account_id,
                "description": proper_description,
                "remediation": remediation_data.get(
                    "text", remediation_data.get("recommendation", "")
                ),
                "compliance": compliance_data,
                "poc_evidence": poc_evidence_text,
                "poc_verification": "",  # Will be set to CLI command by _enhance_finding
                "remediation_commands": remediation_commands,
                "remediation_code": remediation_code,
                "remediation_resources": remediation_resources,
            }
        except Exception as e:
            logger.error(f"Error parsing OCSF finding: {e}")
            return None

    def _parse_prowler_legacy(self, finding_data, cloud_provider="aws"):
        """Parse Prowler legacy format finding"""
        try:
            # Extract account_id from legacy format
            account_id = finding_data.get("AccountId", finding_data.get("account_id", ""))
            if account_id and account_id != "":
                self._discovered_account_id = account_id

            # Determine CLI key based on cloud provider
            cli_key = f"{cloud_provider}_cli"  # aws_cli, azure_cli, gcp_cli

            # Extract remediation details
            remediation_obj = finding_data.get("Remediation", {})
            remediation_text = remediation_obj.get("Recommendation", {})
            if isinstance(remediation_text, dict):
                remediation_text = remediation_text.get("Text", "")

            # Extract CLI and IaC commands
            code_obj = remediation_obj.get("Code", {})
            cli_command = code_obj.get("CLI", "")
            native_iac = code_obj.get("NativeIaC", "")

            # Build remediation commands array with provider-aware description
            remediation_commands = []
            cli_description = "AWS CLI command to remediate"
            if cloud_provider == "azure":
                cli_description = "Azure CLI command to remediate"
            elif cloud_provider == "gcp":
                cli_description = "Google Cloud CLI command to remediate"
            if cli_command:
                remediation_commands.append(
                    {
                        "type": "cli",
                        "command": cli_command,
                        "description": cli_description,
                    }
                )

            # Build remediation code object with provider-specific key
            remediation_code = {}
            if native_iac:
                remediation_code["terraform"] = native_iac
            if cli_command:
                remediation_code[cli_key] = cli_command

            # Build remediation resources with provider-aware title
            remediation_resources = []
            remediation_url = remediation_obj.get("Recommendation", {})
            doc_title = "AWS Documentation"
            if cloud_provider == "azure":
                doc_title = "Azure Documentation"
            elif cloud_provider == "gcp":
                doc_title = "Google Cloud Documentation"
            if isinstance(remediation_url, dict) and remediation_url.get("Url"):
                remediation_resources.append(
                    {
                        "title": doc_title,
                        "url": remediation_url.get("Url"),
                        "type": "documentation",
                    }
                )

            return {
                "check_id": finding_data.get("CheckID", ""),
                "check_title": finding_data.get("CheckTitle", ""),
                "severity": finding_data.get("Severity", "unknown"),
                "status": finding_data.get("Status", ""),
                "region": finding_data.get("Region", "global"),
                "resource_id": finding_data.get("ResourceId", ""),
                "resource_type": finding_data.get("ResourceType", ""),
                "resource_name": finding_data.get(
                    "ResourceName", finding_data.get("ResourceId", "")
                ),
                "account_id": account_id,
                "description": finding_data.get("StatusExtended", ""),
                "remediation": remediation_text
                if isinstance(remediation_text, str)
                else str(remediation_text),
                "compliance": finding_data.get("Compliance", []),
                "poc_evidence": f"Check: {finding_data.get('CheckID', '')}\n"
                    f"Status: {finding_data.get('StatusExtended', '')}\n"
                    f"Risk: {finding_data.get('Risk', '')}\n"
                    f"Resource Details: {finding_data.get('ResourceDetails', '')}",
                "poc_verification": "",  # Will be set to CLI command by _enhance_finding
                "remediation_commands": remediation_commands,
                "remediation_code": remediation_code,
                "remediation_resources": remediation_resources,
            }
        except Exception as e:
            logger.error(f"Error parsing legacy finding: {e}")
            return None

    def process_kube_linter_report(self, report_path):
        """Process kube-linter JSON report"""
        logger.info(f"Processing kube-linter report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            metadata = {
                "tool": "kube-linter",
                "cloud_provider": "kubernetes",
                "scan_date": datetime.now().isoformat(),
            }

            # kube-linter reports array of findings under Reports
            for item in data.get("Reports", []):
                k8s_obj = item.get("Object", {}).get("K8sObject", {})
                for violation in item.get("Violations", []):
                    # Map kube-linter severity levels
                    severity_map = {"error": "high", "warning": "medium", "info": "low"}

                    finding = {
                        "check_id": violation.get("Check", ""),
                        "check_title": violation.get("Check", ""),
                        "severity": severity_map.get(
                            violation.get("Severity", "warning").lower(), "medium"
                        ),
                        "status": "FAIL",
                        "resource_type": k8s_obj.get("GroupVersionKind", {}).get("Kind", ""),
                        "resource_id": f"{k8s_obj.get('Namespace', 'default')}/{k8s_obj.get('Name', '')}",
                        "resource_name": k8s_obj.get("Name", ""),
                        "description": violation.get("Message", ""),
                        "remediation": violation.get("Remediation", ""),
                        "compliance": [],
                    }
                    findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from kube-linter")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing kube-linter report: {e}")
            return None, []

    def process_cloudsploit_report(self, report_path):
        """Process CloudSploit JSON report"""
        logger.info(f"Processing CloudSploit report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            # CloudSploit doesn't include account_id in output, use discovered or parse from path
            account_id = self._discovered_account_id or "unknown"

            metadata = {
                "tool": "cloudsploit",
                "cloud_provider": "aws",
                "scan_date": datetime.now().isoformat(),
                "account_id": account_id,
            }

            # CloudSploit reports are a JSON array of findings
            if not isinstance(data, list):
                logger.warning(f"CloudSploit report is not a JSON array: {report_path}")
                return None, []

            # Map CloudSploit status to severity
            # FAIL -> critical, WARN -> medium, OK -> closed, UNKNOWN -> low
            # We only import FAIL and WARN findings
            status_severity_map = {"FAIL": "critical", "WARN": "medium"}

            for item in data:
                status = item.get("status", "").upper()

                # Filter out OK and UNKNOWN status - only import FAIL and WARN
                if status not in status_severity_map:
                    continue

                severity = status_severity_map[status]

                # Parse compliance info into a structured format
                compliance_text = item.get("compliance", "")
                compliance_frameworks = []
                if compliance_text:
                    # Extract framework name from compliance text (e.g., "PCI: ...")
                    if ":" in compliance_text:
                        framework_name = compliance_text.split(":")[0].strip()
                        compliance_frameworks.append(
                            {
                                "framework": framework_name,
                                "requirement": compliance_text,
                            }
                        )
                    else:
                        compliance_frameworks.append(
                            {"framework": "General", "requirement": compliance_text}
                        )

                # CloudSploit 'message' contains the actual evidence/finding detail
                evidence_message = item.get("message", "")
                resource_id = item.get("resource", "N/A")
                category = item.get("category", "")

                # Build verification text with actual evidence from the scan
                verification_parts = []
                if evidence_message:
                    verification_parts.append("Scan Evidence:")
                    verification_parts.append(f"  {evidence_message}")
                if resource_id and resource_id != "N/A":
                    verification_parts.append(f"\nAffected Resource: {resource_id}")

                poc_verification_text = "\n".join(verification_parts) if verification_parts else ""

                finding = {
                    "check_id": item.get("plugin", ""),
                    "check_title": item.get("title", ""),
                    "severity": severity,
                    "status": "open",
                    "region": item.get("region", "global"),
                    "resource_id": resource_id,
                    "resource_type": category,
                    "resource_name": resource_id,
                    "account_id": account_id,
                    "description": item.get("description", ""),
                    "remediation": "",  # Will be populated by _enhance_finding from KB
                    "compliance": compliance_frameworks,
                    "poc_evidence": json.dumps(
                        {
                            "plugin": item.get("plugin", ""),
                            "category": category,
                            "status": status,
                            "message": evidence_message,
                            "compliance": compliance_text,
                            "resource": resource_id,
                        },
                        indent=2,
                    ),
                    "poc_verification": poc_verification_text,
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [],
                }
                # Enhance finding with KB data (CloudSploit is AWS-only)
                service = item.get("category", "aws")
                check_id = item.get("plugin", "")
                finding = self._enhance_finding(finding, service, check_id, "aws")
                findings.append(finding)

            logger.info(
                f"Extracted {len(findings)} findings from CloudSploit (filtered OK/UNKNOWN)"
            )
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing CloudSploit report: {e}")
            return None, []

    def process_polaris_report(self, report_path):
        """Process Polaris JSON report"""
        logger.info(f"Processing Polaris report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            metadata = {
                "tool": "polaris",
                "cloud_provider": "kubernetes",
                "scan_date": datetime.now().isoformat(),
                "cluster_info": data.get("ClusterInfo", {}),
            }

            # Map Polaris severity to standard severity levels
            severity_map = {
                "danger": "critical",
                "warning": "medium",
                "passing": "info",
            }

            # Process audit results from Results structure
            for namespace_name, namespace_data in data.get("Results", {}).items():
                if not isinstance(namespace_data, dict):
                    continue
                for controller_name, controller_data in namespace_data.items():
                    if not isinstance(controller_data, dict):
                        continue

                    kind = controller_data.get("Kind", "Unknown")

                    for container_name, container_results in controller_data.get(
                        "Results", {}
                    ).items():
                        if not isinstance(container_results, dict):
                            continue

                        for check_category, checks in container_results.items():
                            if not isinstance(checks, dict):
                                continue

                            for check_name, check_result in checks.items():
                                if not isinstance(check_result, dict):
                                    continue

                                # Only report failures
                                if check_result.get("Success", True):
                                    continue

                                severity_level = check_result.get("Severity", "warning")

                                finding = {
                                    "check_id": f"polaris-{check_category}-{check_name}",
                                    "check_title": check_name.replace("_", " ").title(),
                                    "severity": severity_map.get(severity_level, "medium"),
                                    "status": "FAIL",
                                    "resource_type": kind,
                                    "resource_id": f"{namespace_name}/{controller_name}",
                                    "resource_name": controller_name,
                                    "category": check_category,
                                    "container": container_name,
                                    "description": check_result.get("Message", ""),
                                    "remediation": f"Review and fix {check_name} for {kind} {controller_name}",
                                    "compliance": [],
                                }
                                findings.append(finding)

            # Also process PodResults if available (for cluster audits)
            for pod_result in data.get("PodResults", []):
                namespace = pod_result.get("Namespace", "default")
                pod_name = pod_result.get("Name", "")
                kind = pod_result.get("Kind", "Pod")

                for container_result in pod_result.get("ContainerResults", []):
                    container_name = container_result.get("Name", "")

                    for check_name, check_result in container_result.get("Results", {}).items():
                        if not isinstance(check_result, dict):
                            continue
                        if check_result.get("Success", True):
                            continue

                        severity_level = check_result.get("Severity", "warning")

                        finding = {
                            "check_id": f"polaris-{check_name}",
                            "check_title": check_name.replace("_", " ").title(),
                            "severity": severity_map.get(severity_level, "medium"),
                            "status": "FAIL",
                            "resource_type": kind,
                            "resource_id": f"{namespace}/{pod_name}",
                            "resource_name": pod_name,
                            "container": container_name,
                            "description": check_result.get("Message", ""),
                            "remediation": f"Review and fix {check_name} for container {container_name}",
                            "compliance": [],
                        }
                        findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from Polaris")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing Polaris report: {e}")
            return None, []

    def process_checkov_report(self, report_path):
        """Process Checkov JSON report for IaC security findings"""
        logger.info(f"Processing Checkov report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            metadata = {
                "tool": "checkov",
                "cloud_provider": "iac",
                "scan_date": datetime.now().isoformat(),
            }

            # Checkov outputs results per check type (terraform, cloudformation, kubernetes, etc.)
            check_types = data if isinstance(data, list) else [data]

            for check_type_data in check_types:
                check_type = check_type_data.get("check_type", "unknown")

                # Process failed checks
                for check in check_type_data.get("results", {}).get("failed_checks", []):
                    # Map Checkov severity
                    severity_map = {
                        "CRITICAL": "critical",
                        "HIGH": "high",
                        "MEDIUM": "medium",
                        "LOW": "low",
                        "INFO": "info",
                    }
                    # Handle None values (key exists but value is None)
                    raw_severity = check.get("severity") or "MEDIUM"
                    severity = severity_map.get(raw_severity.upper(), "medium")

                    finding = {
                        "check_id": check.get("check_id", ""),
                        "check_title": check.get("check_name", check.get("check_id", "")),
                        "severity": severity,
                        "status": "FAIL",
                        "resource_type": check.get("resource", "").split(".")[-1]
                        if check.get("resource")
                        else check_type,
                        "resource_id": check.get("resource_address", check.get("resource", "")),
                        "resource_name": check.get("resource", ""),
                        "region": "iac",
                        "description": check.get("check_name", ""),
                        "remediation": check.get("guideline", ""),
                        "compliance": [],
                        "poc_evidence": json.dumps(
                            {
                                "check_id": check.get("check_id", ""),
                                "file_path": check.get("file_path", ""),
                                "file_line_range": check.get("file_line_range", []),
                                "code_block": check.get("code_block", ""),
                                "check_class": check.get("check_class", ""),
                            },
                            indent=2,
                        ),
                        "poc_verification": f"File: {check.get('file_path', 'unknown')}\n"
                        f"Lines: {check.get('file_line_range', 'N/A')}",
                        "remediation_commands": [],
                        "remediation_code": {},
                        "remediation_resources": [
                            {
                                "title": "Checkov Documentation",
                                "url": f"https://www.checkov.io/5.Policy%20Index/{check.get('check_id', '')}.html",
                                "type": "documentation",
                            }
                        ]
                        if check.get("check_id")
                        else [],
                    }
                    findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from Checkov")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing Checkov report: {e}")
            return None, []

    def process_terrascan_report(self, report_path):
        """Process Terrascan JSON report for IaC security findings"""
        logger.info(f"Processing Terrascan report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            metadata = {
                "tool": "terrascan",
                "cloud_provider": "iac",
                "scan_date": datetime.now().isoformat(),
            }

            # Terrascan outputs results under 'results'
            results = data.get("results", {})

            # Map Terrascan severity
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            }

            for violation in results.get("violations", []):
                # Handle None values (key exists but value is None)
                raw_severity = violation.get("severity") or "MEDIUM"
                severity = severity_map.get(raw_severity.upper(), "medium")

                finding = {
                    "check_id": violation.get("rule_id", violation.get("rule_name", "")),
                    "check_title": violation.get("rule_name", violation.get("description", "")),
                    "severity": severity,
                    "status": "FAIL",
                    "resource_type": violation.get("resource_type", ""),
                    "resource_id": violation.get("resource_name", violation.get("file", "")),
                    "resource_name": violation.get("resource_name", ""),
                    "region": "iac",
                    "description": violation.get("description", ""),
                    "remediation": violation.get("remediation", ""),
                    "compliance": [],
                    "poc_evidence": json.dumps(
                        {
                            "rule_id": violation.get("rule_id", ""),
                            "file": violation.get("file", ""),
                            "line": violation.get("line", 0),
                            "resource_type": violation.get("resource_type", ""),
                            "category": violation.get("category", ""),
                        },
                        indent=2,
                    ),
                    "poc_verification": f"File: {violation.get('file', 'unknown')}\n"
                    f"Line: {violation.get('line', 'N/A')}",
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [],
                }
                findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from Terrascan")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing Terrascan report: {e}")
            return None, []

    def process_tfsec_report(self, report_path):
        """Process tfsec JSON report for Terraform security findings"""
        logger.info(f"Processing tfsec report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            metadata = {
                "tool": "tfsec",
                "cloud_provider": "iac",
                "scan_date": datetime.now().isoformat(),
            }

            # tfsec outputs results array
            results = data.get("results", []) if isinstance(data, dict) else data

            # Map tfsec severity
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            }

            for result in results:
                # Handle None values (key exists but value is None)
                raw_severity = result.get("severity") or "MEDIUM"
                severity = severity_map.get(raw_severity.upper(), "medium")

                # Extract location info
                location = result.get("location", {})
                filename = location.get("filename", "unknown")
                start_line = location.get("start_line", 0)
                end_line = location.get("end_line", 0)

                finding = {
                    "check_id": result.get("rule_id", result.get("long_id", "")),
                    "check_title": result.get("rule_description", result.get("description", "")),
                    "severity": severity,
                    "status": "FAIL",
                    "resource_type": result.get("resource", "").split(".")[-1]
                    if result.get("resource")
                    else "terraform",
                    "resource_id": result.get("resource", filename),
                    "resource_name": result.get("resource", ""),
                    "region": "iac",
                    "description": result.get("description", ""),
                    "remediation": result.get("resolution", result.get("impact", "")),
                    "compliance": [],
                    "poc_evidence": json.dumps(
                        {
                            "rule_id": result.get("rule_id", ""),
                            "rule_provider": result.get("rule_provider", ""),
                            "rule_service": result.get("rule_service", ""),
                            "file": filename,
                            "lines": f"{start_line}-{end_line}",
                        },
                        indent=2,
                    ),
                    "poc_verification": f"File: {filename}\nLines: {start_line}-{end_line}",
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [
                        {
                            "title": "tfsec Documentation",
                            "url": result["links"][0],
                            "type": "documentation",
                        }
                    ]
                    if result.get("links") and len(result["links"]) > 0
                    else [],
                }
                findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from tfsec")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing tfsec report: {e}")
            return None, []

    def _redact_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Redact a secret value, showing only the first few characters.

        Args:
            secret: The secret value to redact
            visible_chars: Number of characters to show (default: 4)

        Returns:
            Redacted string like "AKIA...REDACTED"
        """
        if not secret or len(secret) <= visible_chars:
            return "[REDACTED]"
        return f"{secret[:visible_chars]}...[REDACTED]"

    def process_trufflehog_report(self, report_path):
        """Process TruffleHog JSON report for secrets scanning"""
        logger.info(f"Processing TruffleHog report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                content = f.read()

            metadata = {
                "tool": "trufflehog",
                "cloud_provider": "secrets",
                "scan_date": datetime.now().isoformat(),
            }

            # TruffleHog outputs newline-delimited JSON
            for line in content.split("\n"):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)

                    # Skip log messages (have "level" field but no "SourceMetadata")
                    if "level" in item and "SourceMetadata" not in item:
                        continue

                    # Skip if this is not a finding (must have SourceMetadata or Raw)
                    if "SourceMetadata" not in item and "Raw" not in item:
                        continue

                    # Extract source metadata
                    source_metadata = item.get("SourceMetadata", {})
                    source_data = source_metadata.get("Data", {})
                    filesystem_data = source_data.get("Filesystem", {})

                    file_path = filesystem_data.get("file", "unknown")
                    line_number = filesystem_data.get("line", 0)

                    # Get detector info
                    detector_name = item.get("DetectorName", "unknown")
                    detector_type = item.get("DetectorType", 0)

                    # Determine if secret was verified
                    verified = item.get("Verified", False)

                    # Map severity based on verification status and detector type
                    if verified:
                        severity = "critical"  # Verified secrets are critical
                    elif detector_name.lower() in ["aws", "gcp", "azure", "github"]:
                        severity = "high"  # Cloud provider secrets are high
                    else:
                        severity = "medium"  # Other secrets are medium

                    # Redact the raw secret value
                    raw_secret = item.get("Raw", "")
                    redacted_secret = self._redact_secret(raw_secret)

                    # Build evidence with redacted secret (ExtraData excluded - may contain sensitive info)
                    evidence_obj = {
                        "detector_name": detector_name,
                        "detector_type": detector_type,
                        "verified": verified,
                        "file": file_path,
                        "line": line_number,
                        "redacted_secret": redacted_secret,
                    }

                    finding = {
                        "check_id": f"trufflehog-{detector_name.lower().replace(' ', '-')}",
                        "check_title": f"Secret Detected: {detector_name}",
                        "severity": severity,
                        "status": "open",
                        "region": "secrets",
                        "resource_id": file_path,
                        "resource_type": "secret",
                        "resource_name": f"{file_path}:{line_number}",
                        "account_id": self._discovered_account_id or "unknown",
                        "description": f"{'Verified ' if verified else ''}secret detected by {detector_name} detector in {file_path} at line {line_number}",
                        "remediation": "Remove the secret from the codebase and rotate the credential immediately. Store secrets in a secure secrets manager.",
                        "compliance": [],
                        "poc_evidence": json.dumps(evidence_obj, indent=2),
                        "poc_verification": f"File: {file_path}\nLine: {line_number}\nDetector: {detector_name}\nVerified: {verified}",
                        "remediation_commands": [],
                        "remediation_code": {},
                        "remediation_resources": [
                            {
                                "title": "TruffleHog Documentation",
                                "url": "https://trufflesecurity.com/trufflehog",
                                "type": "documentation",
                            }
                        ],
                    }
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue

            logger.info(f"Extracted {len(findings)} findings from TruffleHog")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing TruffleHog report: {e}")
            return None, []

    def process_gitleaks_report(self, report_path):
        """Process Gitleaks JSON report for secrets scanning"""
        logger.info(f"Processing Gitleaks report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            metadata = {
                "tool": "gitleaks",
                "cloud_provider": "secrets",
                "scan_date": datetime.now().isoformat(),
            }

            # Gitleaks outputs a JSON array of findings
            if not isinstance(data, list):
                logger.warning(f"Gitleaks report is not a JSON array: {report_path}")
                return None, []

            # High severity rules
            high_severity_rules = {
                "aws-access-key-id", "aws-secret-access-key", "github-pat",
                "github-oauth", "gitlab-pat", "gcp-api-key", "azure-storage-key",
                "private-key", "jwt", "slack-token", "stripe-api-key",
            }

            for item in data:
                rule_id = item.get("RuleID", "unknown")

                # Map severity based on rule type
                if rule_id.lower() in high_severity_rules:
                    severity = "high"
                else:
                    severity = "medium"

                file_path = item.get("File", "unknown")
                line_number = item.get("StartLine", item.get("Line", 0))

                # Redact the secret value
                raw_secret = item.get("Secret", "")
                redacted_secret = self._redact_secret(raw_secret)

                # Build evidence with redacted secret (Match field excluded - may contain secret)
                evidence_obj = {
                    "rule_id": rule_id,
                    "description": item.get("Description", ""),
                    "file": file_path,
                    "start_line": line_number,
                    "end_line": item.get("EndLine", line_number),
                    "redacted_secret": redacted_secret,
                    "fingerprint": item.get("Fingerprint", ""),
                }

                finding = {
                    "check_id": f"gitleaks-{rule_id.lower()}",
                    "check_title": item.get("Description", f"Secret Detected: {rule_id}"),
                    "severity": severity,
                    "status": "open",
                    "region": "secrets",
                    "resource_id": file_path,
                    "resource_type": "secret",
                    "resource_name": f"{file_path}:{line_number}",
                    "account_id": self._discovered_account_id or "unknown",
                    "description": f"Secret detected by {rule_id} rule in {file_path} at line {line_number}. {item.get('Description', '')}",
                    "remediation": "Remove the secret from the codebase and rotate the credential immediately. Store secrets in a secure secrets manager.",
                    "compliance": [],
                    "poc_evidence": json.dumps(evidence_obj, indent=2),
                    "poc_verification": f"File: {file_path}\nLine: {line_number}\nRule: {rule_id}",
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [
                        {
                            "title": "Gitleaks Documentation",
                            "url": "https://github.com/gitleaks/gitleaks",
                            "type": "documentation",
                        }
                    ],
                }
                findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from Gitleaks")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing Gitleaks report: {e}")
            return None, []

    def process_pmapper_report(self, report_path):
        """Process PMapper JSON report for IAM privilege escalation analysis"""
        logger.info(f"Processing PMapper report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            account_id = self._discovered_account_id or "unknown"

            metadata = {
                "tool": "pmapper",
                "cloud_provider": "aws",
                "scan_date": datetime.now().isoformat(),
                "account_id": account_id,
            }

            # PMapper query output format depends on the query type
            # For privesc queries, results contain escalation paths
            if isinstance(data, list):
                for item in data:
                    # Each item is a privilege escalation finding
                    # Use `or` to handle None values from JSON
                    source_principal = item.get("source") or item.get("principal") or "unknown"
                    target_principal = item.get("target") or item.get("admin_principal") or ""
                    escalation_method = item.get("method") or item.get("edge_type") or "unknown"
                    is_admin = item.get("is_admin", False)

                    # Build finding
                    if is_admin:
                        severity = "critical"
                        title = f"Admin Access: {source_principal}"
                        description = f"Principal {source_principal} has admin-level access to the AWS account"
                    elif target_principal:
                        severity = "high"
                        title = f"Privilege Escalation Path: {source_principal}"
                        description = f"Principal {source_principal} can escalate privileges to {target_principal} via {escalation_method}"
                    else:
                        severity = "medium"
                        title = f"IAM Finding: {source_principal}"
                        description = f"IAM finding for principal {source_principal}"

                    evidence_obj = {
                        "source_principal": source_principal,
                        "target_principal": target_principal,
                        "escalation_method": escalation_method,
                        "is_admin": is_admin,
                        "raw_data": item,
                    }

                    finding = {
                        "check_id": f"pmapper-privesc-{escalation_method.lower().replace(' ', '-') if escalation_method else 'unknown'}",
                        "check_title": title,
                        "severity": severity,
                        "status": "open",
                        "region": "global",
                        "resource_id": source_principal,
                        "resource_type": "iam-principal",
                        "resource_name": source_principal.split("/")[-1] if "/" in source_principal else source_principal,
                        "account_id": account_id,
                        "description": description,
                        "remediation": "Review and restrict IAM permissions to follow the principle of least privilege. Remove unnecessary privilege escalation paths.",
                        "compliance": [],
                        "poc_evidence": json.dumps(evidence_obj, indent=2),
                        "poc_verification": f"Source: {source_principal}\nTarget: {target_principal or 'N/A'}\nMethod: {escalation_method}",
                        "remediation_commands": [],
                        "remediation_code": {},
                        "remediation_resources": [
                            {
                                "title": "PMapper Documentation",
                                "url": "https://github.com/nccgroup/PMapper",
                                "type": "documentation",
                            }
                        ],
                    }
                    findings.append(finding)
            elif isinstance(data, dict):
                # Handle graph metadata or summary output
                if "edges" in data:
                    # Process edges for privilege escalation paths
                    for edge in data.get("edges", []):
                        source = edge.get("source", "unknown")
                        destination = edge.get("destination", "")
                        edge_type = edge.get("edge_type", "unknown")

                        evidence_obj = {
                            "source": source,
                            "destination": destination,
                            "edge_type": edge_type,
                        }

                        finding = {
                            "check_id": f"pmapper-edge-{edge_type.lower().replace(' ', '-')}",
                            "check_title": f"IAM Relationship: {edge_type}",
                            "severity": "medium",
                            "status": "open",
                            "region": "global",
                            "resource_id": source,
                            "resource_type": "iam-principal",
                            "resource_name": source.split("/")[-1] if "/" in source else source,
                            "account_id": account_id,
                            "description": f"IAM principal {source} has {edge_type} relationship to {destination}",
                            "remediation": "Review IAM relationships and ensure least privilege access.",
                            "compliance": [],
                            "poc_evidence": json.dumps(evidence_obj, indent=2),
                            "poc_verification": f"Source: {source}\nDestination: {destination}\nType: {edge_type}",
                            "remediation_commands": [],
                            "remediation_code": {},
                            "remediation_resources": [],
                        }
                        findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from PMapper")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing PMapper report: {e}")
            return None, []

    def process_cloudsplaining_report(self, report_path):
        """Process Cloudsplaining JSON report for IAM policy analysis"""
        logger.info(f"Processing Cloudsplaining report: {report_path}")

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)

            account_id = data.get("account_id", self._discovered_account_id or "unknown")

            metadata = {
                "tool": "cloudsplaining",
                "cloud_provider": "aws",
                "scan_date": datetime.now().isoformat(),
                "account_id": account_id,
            }

            # Cloudsplaining outputs different risk categories
            risk_categories = [
                ("privilege_escalation", "critical", "Privilege Escalation"),
                ("resource_exposure", "high", "Resource Exposure"),
                ("infrastructure_modification", "medium", "Infrastructure Modification"),
                ("data_exfiltration", "high", "Data Exfiltration"),
            ]

            # Process findings by risk category
            for category_key, severity, category_name in risk_categories:
                category_findings = data.get(category_key, [])
                if not isinstance(category_findings, list):
                    continue

                for item in category_findings:
                    if isinstance(item, dict):
                        policy_name = item.get("PolicyName", item.get("policy_name", "unknown"))
                        policy_type = item.get("Type", item.get("type", "unknown"))
                        actions = item.get("Actions", item.get("actions", []))
                        services = item.get("Services", item.get("services", []))
                    elif isinstance(item, str):
                        # Some outputs may be just policy names
                        policy_name = item
                        policy_type = "unknown"
                        actions = []
                        services = []
                    else:
                        continue

                    evidence_obj = {
                        "policy_name": policy_name,
                        "policy_type": policy_type,
                        "risk_category": category_key,
                        "actions": actions[:20] if isinstance(actions, list) else [],  # Limit actions
                        "services": services[:10] if isinstance(services, list) else [],
                    }

                    finding = {
                        "check_id": f"cloudsplaining-{category_key.replace('_', '-')}",
                        "check_title": f"{category_name}: {policy_name}",
                        "severity": severity,
                        "status": "open",
                        "region": "global",
                        "resource_id": policy_name,
                        "resource_type": "iam-policy",
                        "resource_name": policy_name,
                        "account_id": account_id,
                        "description": f"IAM policy {policy_name} ({policy_type}) has {category_name.lower()} risk. Affected services: {', '.join(services[:5]) if services else 'N/A'}",
                        "remediation": f"Review and restrict the {policy_name} policy to follow least privilege. Remove unnecessary {category_name.lower()} permissions.",
                        "compliance": [],
                        "poc_evidence": json.dumps(evidence_obj, indent=2),
                        "poc_verification": f"Policy: {policy_name}\nType: {policy_type}\nRisk: {category_name}",
                        "remediation_commands": [],
                        "remediation_code": {},
                        "remediation_resources": [
                            {
                                "title": "Cloudsplaining Documentation",
                                "url": "https://github.com/salesforce/cloudsplaining",
                                "type": "documentation",
                            }
                        ],
                    }
                    findings.append(finding)

            # Also process inline_policies and customer_managed_policies if present
            for policy_section in ["inline_policies", "customer_managed_policies", "aws_managed_policies"]:
                policies = data.get(policy_section, [])
                if not isinstance(policies, list):
                    continue

                for policy in policies:
                    if not isinstance(policy, dict):
                        continue

                    policy_name = policy.get("PolicyName", policy.get("policy_name", "unknown"))
                    risks = policy.get("risks", {})

                    # Process each risk type for this policy
                    for risk_type, risk_actions in risks.items() if isinstance(risks, dict) else []:
                        if not risk_actions:
                            continue

                        # Map risk type to severity
                        risk_severity_map = {
                            "PrivilegeEscalation": "critical",
                            "ResourceExposure": "high",
                            "DataExfiltration": "high",
                            "InfrastructureModification": "medium",
                        }
                        severity = risk_severity_map.get(risk_type, "medium")

                        evidence_obj = {
                            "policy_name": policy_name,
                            "policy_section": policy_section,
                            "risk_type": risk_type,
                            "risky_actions": risk_actions[:20] if isinstance(risk_actions, list) else [],
                        }

                        finding = {
                            "check_id": f"cloudsplaining-policy-{risk_type.lower()}",
                            "check_title": f"{risk_type}: {policy_name}",
                            "severity": severity,
                            "status": "open",
                            "region": "global",
                            "resource_id": policy_name,
                            "resource_type": "iam-policy",
                            "resource_name": policy_name,
                            "account_id": account_id,
                            "description": f"Policy {policy_name} contains {risk_type} risk with {len(risk_actions) if isinstance(risk_actions, list) else 0} risky actions",
                            "remediation": f"Review the {policy_name} policy and remove or restrict {risk_type} permissions.",
                            "compliance": [],
                            "poc_evidence": json.dumps(evidence_obj, indent=2),
                            "poc_verification": f"Policy: {policy_name}\nRisk Type: {risk_type}",
                            "remediation_commands": [],
                            "remediation_code": {},
                            "remediation_resources": [],
                        }
                        findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from Cloudsplaining")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing Cloudsplaining report: {e}")
            return None, []

    def save_to_database(self, metadata, findings, scan_id, existing_scan_id=None):
        """Save processed findings to database.

        Args:
            metadata: Scan metadata dict
            findings: List of finding dicts
            scan_id: Internal scan identifier (tool-specific)
            existing_scan_id: Optional UUID of an existing scan to link findings to.
                             If provided, updates the existing scan record instead of creating new.
        """
        conn = self.connect_db()
        if not conn:
            return False

        try:
            cur = conn.cursor()

            # Apply CVSS-style severity scoring to all findings
            for finding in findings:
                enrich_finding_with_scoring(finding)

            # Apply security enrichments (CISA KEV, K8s CVE, container escape, IMDS)
            try:
                from enrichments import apply_security_enrichments

                for finding in findings:
                    apply_security_enrichments(finding)
                logger.debug("Applied security enrichments to findings")
            except ImportError:
                pass  # Enrichments not available - continue without

            # Count findings by adjusted severity (after scoring)
            critical_count = len(
                [f for f in findings if f.get("severity", "").lower() == "critical"]
            )
            high_count = len([f for f in findings if f.get("severity", "").lower() == "high"])
            medium_count = len([f for f in findings if f.get("severity", "").lower() == "medium"])
            low_count = len([f for f in findings if f.get("severity", "").lower() == "low"])

            # Use existing scan_id if provided, otherwise generate new UUID
            if existing_scan_id:
                db_scan_id = existing_scan_id
                # Update existing scan record with finding counts
                cur.execute(
                    """
                    UPDATE scans SET
                        completed_at = %s,
                        status = 'completed',
                        total_findings = total_findings + %s,
                        critical_findings = critical_findings + %s,
                        high_findings = high_findings + %s,
                        medium_findings = medium_findings + %s,
                        low_findings = low_findings + %s
                    WHERE scan_id = %s
                """,
                    (
                        metadata["scan_date"],
                        len(findings),
                        critical_count,
                        high_count,
                        medium_count,
                        low_count,
                        db_scan_id,
                    ),
                )
                logger.info(f"Updated existing scan {db_scan_id} with {len(findings)} findings")
            else:
                # Generate a proper UUID for the scan
                import uuid

                db_scan_id = str(uuid.uuid4())

                # Insert scan record into 'scans' table (not scan_metadata)
                cur.execute(
                    """
                    INSERT INTO scans (
                        scan_id, scan_type, target, tool,
                        started_at, completed_at, status,
                        total_findings, critical_findings, high_findings,
                        medium_findings, low_findings, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                    (
                        db_scan_id,
                        "security_audit",
                        metadata.get("cloud_provider", "unknown"),
                        metadata["tool"],
                        metadata["scan_date"],
                        metadata["scan_date"],
                        "completed",
                        len(findings),
                        critical_count,
                        high_count,
                        medium_count,
                        low_count,
                        Json(metadata),
                    ),
                )

            # Insert findings with cross-tool deduplication using canonical_id
            for finding in findings:
                # Generate canonical_id for cross-tool deduplication
                canonical_id = self._generate_canonical_id(finding)

                # Use canonical_id as the unique finding_id for true cross-tool deduplication
                # This ensures findings from different tools with the same canonical_id are merged
                finding_unique_id = canonical_id

                # First check if this canonical finding already exists
                cur.execute(
                    """
                    SELECT id, tool_sources, affected_resources FROM findings
                    WHERE finding_id = %s
                """,
                    (finding_unique_id,),
                )
                existing = cur.fetchone()

                if existing:
                    # Merge tool_sources - add new tool if not already present
                    existing_id, existing_tools, existing_resources = existing
                    existing_tools = existing_tools if existing_tools else []
                    existing_resources = existing_resources if existing_resources else []

                    new_tool = metadata["tool"]
                    if new_tool not in existing_tools:
                        existing_tools.append(new_tool)

                    # Merge affected_resources - add new resources
                    new_resources = finding.get("affected_resources", [])
                    existing_resource_ids = {
                        r.get("id") for r in existing_resources if isinstance(r, dict)
                    }
                    for res in new_resources:
                        if isinstance(res, dict) and res.get("id") not in existing_resource_ids:
                            existing_resources.append(res)

                    # Update existing finding with merged data and updated scoring
                    cur.execute(
                        """
                        UPDATE findings SET
                            tool_sources = %s,
                            affected_resources = %s,
                            last_seen = NOW(),
                            scan_id = %s,
                            risk_score = %s,
                            cvss_score = %s,
                            exploitability = %s,
                            severity = %s
                        WHERE id = %s
                    """,
                        (
                            Json(existing_tools),
                            Json(existing_resources),
                            db_scan_id,
                            finding.get("risk_score", 50.0),
                            finding.get("cvss_score", 5.0),
                            finding.get("exploitation_likelihood", "likely"),
                            finding.get("severity", "medium").lower(),
                            existing_id,
                        ),
                    )
                else:
                    # Insert new finding with CVSS-style severity scoring
                    cur.execute(
                        """
                        INSERT INTO findings (
                            finding_id, scan_id, tool, cloud_provider, account_id,
                            region, resource_type, resource_id, resource_name,
                            severity, status, title, description,
                            remediation, compliance_frameworks, metadata,
                            poc_evidence, poc_verification,
                            remediation_commands, remediation_code, remediation_resources,
                            canonical_id, tool_sources, affected_resources,
                            risk_score, cvss_score, exploitability
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                        (
                            finding_unique_id,
                            db_scan_id,
                            metadata["tool"],
                            metadata.get("cloud_provider", "unknown"),
                            finding.get("account_id", metadata.get("account_id", "unknown")),
                            finding.get("region", "global"),
                            finding.get("resource_type", ""),
                            finding.get("resource_id", ""),
                            finding.get("resource_name", finding.get("resource_id", "")),
                            finding.get("severity", "unknown").lower(),
                            finding.get("status", "open").lower()
                            if finding.get("status", "FAIL") != "PASS"
                            else "closed",
                            finding.get("check_title", finding.get("type", "")),
                            finding.get("description", ""),
                            finding.get("remediation", ""),
                            Json(finding.get("compliance", [])),
                            Json(finding),
                            finding.get("poc_evidence", ""),
                            finding.get("poc_verification", ""),
                            Json(finding.get("remediation_commands", [])),
                            Json(finding.get("remediation_code", {})),
                            Json(finding.get("remediation_resources", [])),
                            canonical_id,
                            Json([metadata["tool"]]),  # Initial tool_sources
                            Json(
                                finding.get("affected_resources", [])
                            ),  # Affected resources from parser
                            finding.get("risk_score", 50.0),  # CVSS-style risk score (0-100)
                            finding.get("cvss_score", 5.0),  # CVSS score (0-10)
                            finding.get(
                                "exploitation_likelihood", "likely"
                            ),  # Exploitation likelihood
                        ),
                    )

            conn.commit()
            logger.info(f"Saved {len(findings)} findings to database for scan {db_scan_id}")
            return True

        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()

    def generate_unified_report(self):
        """Generate unified HTML report from all findings"""
        conn = self.connect_db()
        if not conn:
            return

        try:
            # Query all recent findings - using 'scans' table (not scan_metadata)
            query = """
                SELECT f.*, s.tool, s.target as cloud_provider
                FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
                WHERE s.started_at > NOW() - INTERVAL '7 days'
                ORDER BY f.severity DESC, f.finding_id
            """

            df = pd.read_sql(query, conn)

            # Generate summary statistics
            summary = {
                "total_findings": len(df),
                "critical": len(df[df["severity"] == "CRITICAL"]),
                "high": len(df[df["severity"] == "HIGH"]),
                "medium": len(df[df["severity"] == "MEDIUM"]),
                "low": len(df[df["severity"] == "LOW"]),
                "by_region": df.groupby("region").size().to_dict(),
                "by_tool": df.groupby("tool").size().to_dict(),
            }

            # Save summary
            summary_path = (
                self.processed_dir / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)

            logger.info(f"Generated unified report with {summary['total_findings']} findings")

        except Exception as e:
            logger.error(f"Error generating unified report: {e}")
        finally:
            conn.close()

    def _register_scan_files(self, scan_id: str, tool: str, file_paths: list):
        """Register report files associated with a scan in the scan_files table.

        Args:
            scan_id: UUID of the scan
            tool: Tool name (e.g., 'prowler', 'scoutsuite')
            file_paths: List of file paths (Path objects or strings)
        """
        conn = self.connect_db()
        if not conn:
            logger.warning(f"Could not register scan files - database connection failed")
            return

        try:
            cur = conn.cursor()
            for file_path in file_paths:
                path = Path(file_path)
                if not path.exists():
                    continue
                try:
                    file_stat = path.stat()
                    file_type = path.suffix.lstrip(".") or "unknown"
                    cur.execute(
                        """
                        INSERT INTO scan_files (scan_id, tool, file_path, file_type, file_size_bytes)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (scan_id, file_path) DO UPDATE SET
                            file_size_bytes = EXCLUDED.file_size_bytes
                        """,
                        (scan_id, tool, str(path), file_type, file_stat.st_size),
                    )
                except Exception as e:
                    logger.warning(f"Failed to register file {path}: {e}")
            conn.commit()
            logger.info(f"Registered {len(file_paths)} files for scan {scan_id}, tool {tool}")
        except Exception as e:
            logger.error(f"Failed to register scan files: {e}")
            conn.rollback()
        finally:
            conn.close()

    def _log_directory_contents(self, tool_name: str) -> None:
        """Log directory contents for debugging report discovery issues.

        This is called when no reports are found for a tool to help diagnose
        permission issues or unexpected directory structures on Linux systems.
        """
        tool_dir = self.reports_dir / tool_name
        try:
            if not tool_dir.exists():
                logger.warning(f"  Directory does not exist: {tool_dir}")
                return
            if not tool_dir.is_dir():
                logger.warning(f"  Path exists but is not a directory: {tool_dir}")
                return

            # Check if directory is readable
            try:
                contents = list(tool_dir.iterdir())
            except PermissionError:
                logger.error(f"  Permission denied reading directory: {tool_dir}")
                logger.error("  On Linux, run: sudo chmod -R 755 ./reports")
                return

            if not contents:
                logger.warning(f"  Directory is empty: {tool_dir}")
                return

            logger.info(f"  Directory contents of {tool_dir}:")
            for item in contents[:10]:  # Limit to first 10 items
                try:
                    stat_info = item.stat()
                    mode = oct(stat_info.st_mode)[-3:]
                    logger.info(f"    {item.name} (mode: {mode})")
                except PermissionError:
                    logger.warning(f"    {item.name} (permission denied)")
            if len(contents) > 10:
                logger.info(f"    ... and {len(contents) - 10} more items")

        except Exception as e:
            logger.error(f"  Error listing directory {tool_dir}: {e}")

    def process_for_scan(self, orchestration_scan_id: str, tools: list = None):
        """Process reports and link findings to an existing orchestration scan.

        This method is called by the scan orchestration after tools complete.
        It processes only reports generated by the specified tools and links
        all findings to the orchestration's scan_id.

        Args:
            orchestration_scan_id: UUID of the existing scan record from orchestration
            tools: Optional list of tools to process (e.g., ['prowler', 'scoutsuite'])
                  If None, processes all available reports.

        Returns:
            int: Total number of findings processed
        """
        logger.info(f"Processing reports for orchestration scan: {orchestration_scan_id}")
        logger.info(f"Reports directory: {self.reports_dir}")
        logger.info(f"Reports directory exists: {self.reports_dir.exists()}")

        # Check reports directory accessibility
        if not self.reports_dir.exists():
            logger.error(f"Reports directory does not exist: {self.reports_dir}")
            return 0
        try:
            list(self.reports_dir.iterdir())
        except PermissionError:
            logger.error(f"Permission denied accessing reports directory: {self.reports_dir}")
            logger.error("On Linux, run: sudo chmod -R 755 ./reports")
            return 0

        total_findings = 0
        processed_files = {}  # tool -> list of file paths

        # Process each tool's reports
        tools_to_process = tools or [
            "prowler", "scoutsuite", "cloudsploit", "cloudfox",
            "trufflehog", "gitleaks", "pmapper", "cloudsplaining"
        ]
        logger.info(f"Tools to process: {tools_to_process}")

        if "prowler" in tools_to_process:
            # Process most recent Prowler reports
            prowler_reports = list(self.reports_dir.glob("prowler/*/prowler-output-*.json"))
            prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.json"))
            prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.ocsf.json"))
            prowler_reports = list(set(prowler_reports))
            logger.info(f"Found {len(prowler_reports)} Prowler report(s)")
            # Sort by modification time, process most recent
            if prowler_reports:
                prowler_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = prowler_reports[0]
                logger.info(f"Processing Prowler report: {report}")
                metadata, findings = self.process_prowler_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"prowler_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    # Track processed file for registration
                    processed_files["prowler"] = [str(report)]
                else:
                    logger.warning(f"Prowler report yielded no findings: {report}")
            else:
                logger.warning("No Prowler reports found. Checking directory contents...")
                self._log_directory_contents("prowler")

        if "prowler-azure" in tools_to_process:
            # Process most recent Prowler Azure reports (same format as AWS Prowler)
            prowler_azure_reports = list(self.reports_dir.glob("prowler-azure/*/prowler-output-*.json"))
            prowler_azure_reports += list(self.reports_dir.glob("prowler-azure/prowler-output-*.json"))
            prowler_azure_reports += list(self.reports_dir.glob("prowler-azure/prowler-output-*.ocsf.json"))
            prowler_azure_reports = list(set(prowler_azure_reports))
            logger.info(f"Found {len(prowler_azure_reports)} Prowler Azure report(s)")
            # Sort by modification time, process most recent
            if prowler_azure_reports:
                prowler_azure_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = prowler_azure_reports[0]
                logger.info(f"Processing Prowler Azure report: {report}")
                metadata, findings = self.process_prowler_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"prowler_azure_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    # Track processed file for registration
                    processed_files["prowler-azure"] = [str(report)]
                else:
                    logger.warning(f"Prowler Azure report yielded no findings: {report}")
            else:
                logger.warning("No Prowler Azure reports found. Checking directory contents...")
                self._log_directory_contents("prowler-azure")

        if "scoutsuite" in tools_to_process:
            # Process most recent ScoutSuite reports
            # NOTE: Filter to only scoutsuite_results files, not scoutsuite_exceptions
            scoutsuite_reports = list(
                self.reports_dir.glob("scoutsuite/*/scoutsuite-results/scoutsuite_results*.js")
            )
            scoutsuite_reports += list(
                self.reports_dir.glob("scoutsuite/*/scoutsuite_results_*.json")
            )
            scoutsuite_reports = list(set(scoutsuite_reports))
            logger.info(f"Found {len(scoutsuite_reports)} ScoutSuite report(s)")
            if scoutsuite_reports:
                scoutsuite_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = scoutsuite_reports[0]
                logger.info(f"Processing ScoutSuite report: {report}")
                metadata, findings = self.process_scoutsuite_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"scoutsuite_{report.parent.name}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    # Track processed file for registration
                    processed_files["scoutsuite"] = [str(report)]
                else:
                    logger.warning(f"ScoutSuite report yielded no findings: {report}")
            else:
                logger.warning("No ScoutSuite reports found. Checking directory contents...")
                self._log_directory_contents("scoutsuite")

        if "scoutsuite-azure" in tools_to_process:
            # Process most recent ScoutSuite Azure reports (same format as AWS ScoutSuite)
            scoutsuite_azure_reports = list(
                self.reports_dir.glob("scoutsuite/azure/scoutsuite-results/scoutsuite_results*.js")
            )
            scoutsuite_azure_reports += list(
                self.reports_dir.glob("scoutsuite/azure/scoutsuite_results_*.json")
            )
            scoutsuite_azure_reports = list(set(scoutsuite_azure_reports))
            logger.info(f"Found {len(scoutsuite_azure_reports)} ScoutSuite Azure report(s)")
            if scoutsuite_azure_reports:
                scoutsuite_azure_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = scoutsuite_azure_reports[0]
                logger.info(f"Processing ScoutSuite Azure report: {report}")
                metadata, findings = self.process_scoutsuite_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"scoutsuite_azure_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["scoutsuite-azure"] = [str(report)]
                else:
                    logger.warning(f"ScoutSuite Azure report yielded no findings: {report}")
            else:
                logger.warning("No ScoutSuite Azure reports found.")

        if "cloudsploit" in tools_to_process:
            # Process most recent CloudSploit reports
            cloudsploit_reports = list(self.reports_dir.glob("cloudsploit/*.json"))
            logger.info(f"Found {len(cloudsploit_reports)} CloudSploit report(s)")
            if cloudsploit_reports:
                cloudsploit_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = cloudsploit_reports[0]
                logger.info(f"Processing CloudSploit report: {report}")
                metadata, findings = self.process_cloudsploit_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"cloudsploit_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    # Track processed file for registration
                    processed_files["cloudsploit"] = [str(report)]
                else:
                    logger.warning(f"CloudSploit report yielded no findings: {report}")
            else:
                logger.warning("No CloudSploit reports found. Checking directory contents...")
                self._log_directory_contents("cloudsploit")

        if "cloudfox" in tools_to_process:
            # CloudFox outputs are enumeration data (inventory, permissions, principals)
            # stored in cloudfox_results table, not as security findings
            # The data supports attack path analysis but isn't findings-based
            cloudfox_output_dir = self.reports_dir / "cloudfox" / "cloudfox-output"
            if cloudfox_output_dir.exists():
                json_files = list(cloudfox_output_dir.glob("**/*.json"))
                if json_files:
                    logger.info(
                        f"CloudFox: Found {len(json_files)} enumeration files (stored in cloudfox_results table)"
                    )
                    # Track CloudFox files for registration
                    processed_files["cloudfox"] = [str(f) for f in json_files]
                    # CloudFox enumeration data powers attack path analysis
                    # Findings from CloudFox are generated via attack_path_analyzer.py

        # ========================================================================
        # IaC Security Tools
        # ========================================================================

        if "checkov" in tools_to_process:
            # Process Checkov reports
            checkov_reports = list(self.reports_dir.glob("checkov/*.json"))
            checkov_reports += list(self.reports_dir.glob("checkov/results*.json"))
            checkov_reports = list(set(checkov_reports))
            if checkov_reports:
                checkov_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = checkov_reports[0]
                logger.info(f"Processing Checkov report: {report}")
                metadata, findings = self.process_checkov_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"checkov_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["checkov"] = [str(report)]

        if "terrascan" in tools_to_process:
            # Process Terrascan reports
            terrascan_reports = list(self.reports_dir.glob("terrascan/*.json"))
            terrascan_reports += list(self.reports_dir.glob("terrascan/terrascan-results*.json"))
            terrascan_reports = list(set(terrascan_reports))
            if terrascan_reports:
                terrascan_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = terrascan_reports[0]
                logger.info(f"Processing Terrascan report: {report}")
                metadata, findings = self.process_terrascan_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"terrascan_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["terrascan"] = [str(report)]

        if "tfsec" in tools_to_process:
            # Process tfsec reports
            tfsec_reports = list(self.reports_dir.glob("tfsec/*.json"))
            tfsec_reports += list(self.reports_dir.glob("tfsec/tfsec-*.json"))
            tfsec_reports = list(set(tfsec_reports))
            if tfsec_reports:
                tfsec_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = tfsec_reports[0]
                logger.info(f"Processing tfsec report: {report}")
                metadata, findings = self.process_tfsec_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"tfsec_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["tfsec"] = [str(report)]

        if "kube-linter" in tools_to_process:
            # Process kube-linter reports
            kube_linter_reports = list(self.reports_dir.glob("kube-linter/*.json"))
            if kube_linter_reports:
                kube_linter_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = kube_linter_reports[0]
                logger.info(f"Processing kube-linter report: {report}")
                metadata, findings = self.process_kube_linter_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"kube_linter_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["kube-linter"] = [str(report)]

        if "polaris" in tools_to_process:
            # Process Polaris reports
            polaris_reports = list(self.reports_dir.glob("polaris/*.json"))
            polaris_reports += list(self.reports_dir.glob("polaris/polaris-*.json"))
            polaris_reports = list(set(polaris_reports))
            if polaris_reports:
                polaris_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = polaris_reports[0]
                logger.info(f"Processing Polaris report: {report}")
                metadata, findings = self.process_polaris_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"polaris_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["polaris"] = [str(report)]

        # ========================================================================
        # Secrets Scanning Tools
        # ========================================================================

        if "trufflehog" in tools_to_process:
            # Process TruffleHog reports (newline-delimited JSON output)
            trufflehog_reports = list(self.reports_dir.glob("trufflehog/*.json"))
            trufflehog_reports += list(self.reports_dir.glob("trufflehog/results.json"))
            trufflehog_reports = list(set(trufflehog_reports))
            if trufflehog_reports:
                trufflehog_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = trufflehog_reports[0]
                logger.info(f"Processing TruffleHog report: {report}")
                metadata, findings = self.process_trufflehog_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"trufflehog_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["trufflehog"] = [str(report)]

        if "gitleaks" in tools_to_process:
            # Process Gitleaks reports
            gitleaks_reports = list(self.reports_dir.glob("gitleaks/*.json"))
            gitleaks_reports += list(self.reports_dir.glob("gitleaks/results.json"))
            gitleaks_reports = list(set(gitleaks_reports))
            if gitleaks_reports:
                gitleaks_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = gitleaks_reports[0]
                logger.info(f"Processing Gitleaks report: {report}")
                metadata, findings = self.process_gitleaks_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"gitleaks_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["gitleaks"] = [str(report)]

        # ========================================================================
        # IAM Deep Analysis Tools
        # ========================================================================

        if "pmapper" in tools_to_process:
            # Process PMapper reports
            pmapper_reports = list(self.reports_dir.glob("pmapper/*.json"))
            pmapper_reports += list(self.reports_dir.glob("pmapper/privesc-*.json"))
            pmapper_reports = list(set(pmapper_reports))
            if pmapper_reports:
                pmapper_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = pmapper_reports[0]
                logger.info(f"Processing PMapper report: {report}")
                metadata, findings = self.process_pmapper_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"pmapper_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["pmapper"] = [str(report)]

        if "cloudsplaining" in tools_to_process:
            # Process Cloudsplaining reports
            cloudsplaining_reports = list(self.reports_dir.glob("cloudsplaining/*.json"))
            cloudsplaining_reports += list(self.reports_dir.glob("cloudsplaining/*-iam-results.json"))
            cloudsplaining_reports = list(set(cloudsplaining_reports))
            if cloudsplaining_reports:
                cloudsplaining_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = cloudsplaining_reports[0]
                logger.info(f"Processing Cloudsplaining report: {report}")
                metadata, findings = self.process_cloudsplaining_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"cloudsplaining_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["cloudsplaining"] = [str(report)]

        # Register all processed files with the scan
        for tool, files in processed_files.items():
            if files:
                self._register_scan_files(orchestration_scan_id, tool, files)

        # ========================================================================
        # Attack Validation Features (v2)
        # ========================================================================
        self._run_attack_validation_features(orchestration_scan_id)

        # Summary logging with diagnostic hints
        if total_findings == 0:
            logger.warning(
                f"ZERO findings processed for scan {orchestration_scan_id}. "
                "This may indicate a problem with report discovery or permissions."
            )
            logger.warning(f"Tools requested: {tools_to_process}")
            logger.warning(f"Processed files: {processed_files}")
            logger.warning(
                "If running on Linux, ensure reports directory is readable: "
                "sudo chmod -R 755 ./reports"
            )
        else:
            logger.info(f"Successfully processed {total_findings} findings for scan {orchestration_scan_id}")
            logger.info(f"Processed files by tool: {list(processed_files.keys())}")

        return total_findings

    def _run_attack_validation_features(self, scan_id: str):
        """Run attack validation features based on user settings.

        Features (v2):
        - Blast Radius Analysis: Calculate impact of compromised identities
        - PoC Validation: Test if attack paths are exploitable (if enabled)
        - Runtime Correlation: Link findings to CloudTrail events (if enabled)

        Args:
            scan_id: UUID of the scan to run validation features for
        """
        # Get user settings to determine which features to run
        settings = self._get_validation_settings()

        # Blast Radius Analysis (default: auto-enabled)
        if settings.get("blast_radius_auto_analyze", True) and BlastRadiusAnalyzer:
            try:
                logger.info(f"Running blast radius analysis for scan {scan_id}")
                analyzer = BlastRadiusAnalyzer(self.conn)
                results = analyzer.analyze_for_scan(scan_id)
                logger.info(f"Blast radius analysis complete: {len(results)} identities analyzed")
            except Exception as e:
                logger.warning(f"Blast radius analysis failed (non-fatal): {e}")

        # PoC Validation (default: disabled, requires explicit opt-in)
        if settings.get("auto_validate_poc", False) and PoCValidator:
            try:
                logger.info(f"Running PoC validation for scan {scan_id}")
                validator = PoCValidator(self.conn)
                # Only validate high-severity attack paths
                results = validator.validate_attack_paths_for_scan(scan_id, severity_filter="high")
                validated = sum(1 for r in results if r.get("validation_status") == "validated_exploitable")
                logger.info(f"PoC validation complete: {validated}/{len(results)} paths validated as exploitable")
            except Exception as e:
                logger.warning(f"PoC validation failed (non-fatal): {e}")

        # Runtime Correlation (default: disabled, requires CloudTrail access)
        if settings.get("cloudtrail_correlation", False) and RuntimeCorrelator:
            try:
                logger.info(f"Running runtime correlation for scan {scan_id}")
                lookback_hours = int(settings.get("cloudtrail_lookback_hours", 24))
                correlator = RuntimeCorrelator(self.conn)
                results = correlator.correlate_for_scan(scan_id, lookback_hours=lookback_hours)
                confirmed = sum(1 for r in results if r.get("confirms_exploitability", False))
                logger.info(f"Runtime correlation complete: {confirmed} findings confirmed by CloudTrail events")
            except Exception as e:
                logger.warning(f"Runtime correlation failed (non-fatal): {e}")

    def _get_validation_settings(self) -> dict:
        """Retrieve validation feature settings from user_settings table.

        Returns:
            Dictionary of setting_key -> setting_value for validation features.
        """
        settings = {}
        validation_keys = [
            "auto_validate_poc",
            "cloudtrail_correlation",
            "blast_radius_auto_analyze",
            "poc_validation_timeout",
            "cloudtrail_lookback_hours",
        ]
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT setting_key, setting_value
                    FROM user_settings
                    WHERE setting_key = ANY(%s)
                    """,
                    (validation_keys,),
                )
                for row in cur.fetchall():
                    key, value = row
                    # Convert boolean strings
                    if value.lower() in ("true", "false"):
                        settings[key] = value.lower() == "true"
                    else:
                        settings[key] = value
        except Exception as e:
            logger.debug(f"Could not retrieve validation settings: {e}")
        return settings

    def run(self):
        """Main processing loop"""
        logger.info("Starting report processing...")

        # Process ScoutSuite reports (JavaScript format in scoutsuite-results/ subdirectory)
        scoutsuite_reports = list(self.reports_dir.glob("scoutsuite/*/scoutsuite-results/*.js"))
        # Also support legacy JSON format for backwards compatibility
        scoutsuite_reports += list(self.reports_dir.glob("scoutsuite/*/scoutsuite_results_*.json"))
        # Deduplicate in case patterns overlap
        scoutsuite_reports = list(set(scoutsuite_reports))
        for report in scoutsuite_reports:
            scan_id = f"scoutsuite_{report.parent.parent.name if report.suffix == '.js' else report.parent.name}"
            metadata, findings = self.process_scoutsuite_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process Prowler reports (both legacy and OCSF formats)
        prowler_reports = list(self.reports_dir.glob("prowler/*/prowler-output-*.json"))
        prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.json"))
        prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.ocsf.json"))
        # Deduplicate in case patterns overlap
        prowler_reports = list(set(prowler_reports))
        for report in prowler_reports:
            scan_id = f"prowler_{report.stem}"
            metadata, findings = self.process_prowler_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process kube-linter reports
        kube_linter_reports = list(self.reports_dir.glob("kube-linter/*.json"))
        for report in kube_linter_reports:
            scan_id = f"kube_linter_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_kube_linter_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process Polaris reports
        polaris_reports = list(self.reports_dir.glob("polaris/*.json"))
        for report in polaris_reports:
            scan_id = f"polaris_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_polaris_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process CloudSploit reports
        cloudsploit_reports = list(self.reports_dir.glob("cloudsploit/*.json"))
        for report in cloudsploit_reports:
            scan_id = f"cloudsploit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_cloudsploit_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Generate unified report
        self.generate_unified_report()

        logger.info("Report processing completed")


if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(description="Process security scan reports")
    parser.add_argument(
        "--scan-id", dest="scan_id", help="Orchestration scan UUID to link findings to"
    )
    parser.add_argument(
        "--tools",
        dest="tools",
        help="Comma-separated list of tools to process (e.g., prowler,scoutsuite)",
    )
    parser.add_argument(
        "--auto-process",
        dest="auto_process",
        action="store_true",
        help="Auto-process all existing reports on startup",
    )
    args = parser.parse_args()

    # Also check environment variables (for container deployment)
    scan_id = args.scan_id or os.environ.get("ORCHESTRATION_SCAN_ID")
    tools_str = args.tools or os.environ.get("TOOLS_TO_PROCESS")
    tools = tools_str.split(",") if tools_str else None

    # Check if auto-processing is enabled (default: disabled)
    auto_process = args.auto_process or os.environ.get("AUTO_PROCESS", "false").lower() == "true"

    processor = ReportProcessor()

    if scan_id:
        # Process for a specific orchestration scan
        logger.info(f"Processing reports for orchestration scan: {scan_id}")
        total = processor.process_for_scan(scan_id, tools)
        logger.info(f"Completed: {total} findings linked to scan {scan_id}")
    elif auto_process:
        # Run full processing loop only if explicitly enabled
        logger.info("Auto-processing enabled, running full report processing")
        processor.run()
    else:
        # Default: wait for explicit triggers (scans will trigger processing via API)
        logger.info("Report processor started in standby mode (AUTO_PROCESS=false)")
        logger.info("Processing will be triggered by scan completions via API")
        # Keep container alive but don't auto-process
        while True:
            time.sleep(3600)  # Sleep for 1 hour, wake up to check for signals
