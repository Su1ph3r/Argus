"""PoC Validation Engine - Validates attack paths using safe read-only commands.

This module provides a secure way to validate whether attack paths and privilege
escalation paths are actually exploitable by executing only safe, read-only
commands against cloud environments.

Security Features:
- Strict allowlist of safe commands (describe/list/get only)
- Blocklist of dangerous operations (delete/create/update/etc.)
- Command transformation to safe equivalents
- Execution in isolated subprocess with timeout
- Evidence capture for audit trail
- No shell expansion (shell=False always)
"""

import hashlib
import json
import logging
import re
import shlex
import subprocess
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================================
# Safety Mechanisms - ONLY these commands are allowed
# ============================================================================

# Allowed command prefixes/patterns for each CLI tool
ALLOWED_COMMANDS: dict[str, list[str]] = {
    "aws": [
        "describe-",
        "list-",
        "get-",
        "sts get-caller-identity",
        "iam get-user",
        "iam get-role",
        "iam get-policy",
        "iam get-policy-version",
        "iam list-attached-",
        "iam list-role-policies",
        "iam list-user-policies",
        "iam list-groups",
        "s3api head-bucket",
        "s3api head-object",
        "s3api get-bucket-acl",
        "s3api get-bucket-policy",
        "s3api get-bucket-versioning",
        "s3api get-bucket-encryption",
        "s3api get-public-access-block",
        "ec2 describe-",
        "rds describe-",
        "lambda get-function",
        "lambda get-policy",
        "lambda list-",
        "kms describe-",
        "kms list-",
        "kms get-key-policy",
        "secretsmanager describe-",
        "secretsmanager list-",
        "ssm describe-",
        "ssm list-",
        "ssm get-parameter",  # Read-only, doesn't execute
        "ecs describe-",
        "ecs list-",
        "eks describe-",
        "eks list-",
        "ecr describe-",
        "ecr list-",
        "ecr get-",
        "cloudtrail describe-",
        "cloudtrail list-",
        "cloudtrail get-",
        "organizations describe-",
        "organizations list-",
        "route53 list-",
        "route53 get-",
        "cloudfront list-",
        "cloudfront get-",
        "elasticloadbalancing describe-",
        "elbv2 describe-",
        "autoscaling describe-",
        "sns list-",
        "sns get-",
        "sqs list-",
        "sqs get-",
        "dynamodb describe-",
        "dynamodb list-",
    ],
    "az": [
        "account show",
        "account list",
        "ad user show",
        "ad user list",
        "ad group show",
        "ad group list",
        "ad sp show",
        "ad sp list",
        "role assignment list",
        "role definition list",
        "storage account show",
        "storage account list",
        "storage container list",
        "storage blob list",
        "network nsg show",
        "network nsg list",
        "network vnet show",
        "network vnet list",
        "vm show",
        "vm list",
        "keyvault show",
        "keyvault list",
        "keyvault secret list",  # Lists names only, not values
        "webapp show",
        "webapp list",
        "functionapp show",
        "functionapp list",
        "sql server show",
        "sql server list",
        "cosmosdb show",
        "cosmosdb list",
        "aks show",
        "aks list",
        "acr show",
        "acr list",
    ],
    "gcloud": [
        "projects list",
        "projects describe",
        "iam service-accounts list",
        "iam service-accounts describe",
        "iam roles list",
        "iam roles describe",
        "compute instances list",
        "compute instances describe",
        "compute networks list",
        "compute networks describe",
        "compute firewall-rules list",
        "compute firewall-rules describe",
        "storage buckets list",
        "storage buckets describe",
        "container clusters list",
        "container clusters describe",
        "sql instances list",
        "sql instances describe",
        "functions list",
        "functions describe",
        "pubsub topics list",
        "pubsub subscriptions list",
        "secrets list",
        "kms keyrings list",
        "kms keys list",
    ],
}

# Commands that are ALWAYS blocked, regardless of context
BLOCKED_COMMANDS: list[str] = [
    "delete",
    "create",
    "update",
    "put",
    "modify",
    "attach",
    "detach",
    "remove",
    "terminate",
    "stop",
    "start",
    "reboot",
    "invoke",
    "execute",
    "run",
    "send",
    "publish",
    "write",
    "set",
    "enable",
    "disable",
    "reset",
    "rotate",
    "revoke",
    "grant",
    "assume-role",  # Could lead to privilege escalation
    "get-session-token",
    "get-federation-token",
    "--execute",
    "--run",
    "; ",
    "&&",
    "||",
    "|",
    "`",
    "$(",
    "$((",
    ">",
    "<",
    ">>",
    "<<",
]

# Patterns that indicate dangerous commands
BLOCKED_PATTERNS: list[str] = [
    r"--cli-input-json",  # Could contain arbitrary operations
    r"--generate-cli-skeleton",  # Not dangerous but not useful
    r"fileb://",  # File uploads
    r"file://",  # File references
    r"s3://.*--acl",  # ACL modifications
    r"--policy\s+\{",  # Inline policies
    r"--policy-document",  # Policy modifications
]


class ValidationResult:
    """Result of a single validation step."""

    def __init__(
        self,
        command: str,
        success: bool,
        output: str | None = None,
        error: str | None = None,
        timestamp: datetime | None = None,
    ):
        self.command = command
        self.success = success
        self.output = output
        self.error = error
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "command": self.command,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class PoCValidator:
    """Validates attack paths using safe read-only commands.

    This class provides mechanisms to safely execute validation commands
    against cloud environments to determine if attack paths are actually
    exploitable.

    Security:
    - Only executes commands from strict allowlist
    - Blocks all write/modify/delete operations
    - Uses subprocess with shell=False
    - Enforces timeout on all executions
    - Logs all execution attempts for audit
    """

    def __init__(self, timeout: int = 30, max_output_size: int = 65536):
        """Initialize the PoC validator.

        Args:
            timeout: Maximum seconds to wait for command execution (default: 30)
            max_output_size: Maximum bytes of output to capture (default: 64KB)
        """
        self.timeout = timeout
        self.max_output_size = max_output_size

    def is_safe_command(self, command: str) -> tuple[bool, str]:
        """Check if command is safe (read-only) for execution.

        Args:
            command: The full command string to validate

        Returns:
            Tuple of (is_safe, reason)
            - (True, "Safe: ...") if command is allowed
            - (False, "Blocked: ...") if command is dangerous
        """
        if not command or not command.strip():
            return False, "Blocked: Empty command"

        command_lower = command.lower().strip()

        # Check for blocked commands first (highest priority)
        for blocked in BLOCKED_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: Contains dangerous keyword '{blocked}'"

        # Check for blocked patterns
        for pattern in BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Blocked: Matches dangerous pattern '{pattern}'"

        # Determine the CLI tool being used
        parts = shlex.split(command)
        if not parts:
            return False, "Blocked: Could not parse command"

        cli_tool = parts[0].lower()

        # Check if the CLI tool is known
        if cli_tool not in ALLOWED_COMMANDS:
            return False, f"Blocked: Unknown CLI tool '{cli_tool}'"

        # Get the subcommand(s) for validation
        subcommand = " ".join(parts[1:]).lower() if len(parts) > 1 else ""

        # Check if the subcommand matches any allowed pattern
        allowed_patterns = ALLOWED_COMMANDS[cli_tool]
        for allowed in allowed_patterns:
            if subcommand.startswith(allowed.lower()):
                return True, f"Safe: Matches allowed pattern '{allowed}'"

        return False, f"Blocked: Subcommand not in allowlist for '{cli_tool}'"

    def transform_to_safe_command(self, poc_step: dict[str, Any]) -> str | None:
        """Transform a PoC step to its safe read-only equivalent.

        Takes a PoC step that might contain a dangerous command and attempts
        to transform it into a safe verification command that validates
        the same condition without making changes.

        Args:
            poc_step: Dictionary containing at least 'command' key

        Returns:
            Safe command string, or None if transformation not possible
        """
        original_command = poc_step.get("command", "")
        if not original_command:
            return None

        # Try to parse the command
        try:
            parts = shlex.split(original_command)
        except ValueError:
            logger.warning(f"Could not parse command: {original_command[:100]}")
            return None

        if not parts:
            return None

        cli_tool = parts[0].lower()

        # Define transformation rules for common dangerous -> safe equivalents
        transformations: dict[str, dict[str, str]] = {
            "aws": {
                # IAM operations
                "iam attach-": "iam list-attached-",
                "iam put-": "iam get-",
                "iam create-": "iam get-",
                "iam update-": "iam get-",
                "iam delete-": "iam get-",
                # S3 operations
                "s3 cp ": "s3api head-object --bucket {bucket} --key {key}",
                "s3 rm ": "s3api head-object --bucket {bucket} --key {key}",
                "s3api put-": "s3api get-",
                "s3api delete-": "s3api get-",
                # EC2 operations
                "ec2 run-instances": "ec2 describe-instances",
                "ec2 terminate-instances": "ec2 describe-instances --instance-ids",
                "ec2 start-instances": "ec2 describe-instances --instance-ids",
                "ec2 stop-instances": "ec2 describe-instances --instance-ids",
                "ec2 modify-": "ec2 describe-",
                "ec2 create-": "ec2 describe-",
                "ec2 delete-": "ec2 describe-",
                # Lambda operations
                "lambda invoke": "lambda get-function --function-name",
                "lambda update-": "lambda get-function --function-name",
                "lambda create-": "lambda list-functions",
                "lambda delete-": "lambda get-function --function-name",
                # RDS operations
                "rds create-": "rds describe-db-instances",
                "rds delete-": "rds describe-db-instances",
                "rds modify-": "rds describe-db-instances",
                # Secrets Manager
                "secretsmanager get-secret-value": "secretsmanager describe-secret --secret-id",
                "secretsmanager put-": "secretsmanager describe-secret --secret-id",
                "secretsmanager delete-": "secretsmanager describe-secret --secret-id",
                # KMS operations
                "kms encrypt": "kms describe-key --key-id",
                "kms decrypt": "kms describe-key --key-id",
                "kms create-": "kms list-keys",
                "kms schedule-": "kms describe-key --key-id",
                # STS operations - verify identity instead
                "sts assume-role": "sts get-caller-identity",
                "sts get-session-token": "sts get-caller-identity",
            },
            "az": {
                # Storage operations
                "storage blob upload": "storage blob list --container-name",
                "storage blob delete": "storage blob list --container-name",
                # Role operations
                "role assignment create": "role assignment list",
                "role assignment delete": "role assignment list",
                # VM operations
                "vm create": "vm list",
                "vm delete": "vm show",
                "vm start": "vm show",
                "vm stop": "vm show",
                # Keyvault secrets
                "keyvault secret set": "keyvault secret list",
                "keyvault secret delete": "keyvault secret list",
            },
        }

        if cli_tool not in transformations:
            return None

        # Get the subcommand for transformation lookup
        subcommand = " ".join(parts[1:]).lower() if len(parts) > 1 else ""

        # Find a matching transformation
        for dangerous_pattern, safe_pattern in transformations[cli_tool].items():
            if subcommand.startswith(dangerous_pattern.lower()):
                # Build the safe command
                # For simple prefix replacements
                if not safe_pattern.startswith(dangerous_pattern.split()[0]):
                    # It's a different command structure
                    safe_cmd = f"{cli_tool} {safe_pattern}"
                else:
                    # Replace the prefix
                    safe_cmd = (
                        f"{cli_tool} {safe_pattern}{subcommand[len(dangerous_pattern):]}"
                    )

                # Validate the transformed command is actually safe
                is_safe, reason = self.is_safe_command(safe_cmd)
                if is_safe:
                    logger.info(
                        f"Transformed dangerous command to safe equivalent: {safe_cmd[:100]}"
                    )
                    return safe_cmd
                else:
                    logger.warning(
                        f"Transformed command still not safe: {safe_cmd[:100]} - {reason}"
                    )
                    return None

        # If the command is already safe, return it
        is_safe, _ = self.is_safe_command(original_command)
        if is_safe:
            return original_command

        return None

    def execute_safe_command(self, command: str) -> ValidationResult:
        """Execute a safe command and capture evidence.

        This method ONLY executes commands that pass the is_safe_command check.
        All execution is done with shell=False to prevent shell injection.

        Args:
            command: The command to execute (must pass safety check)

        Returns:
            ValidationResult with execution details and evidence
        """
        # First, validate the command is safe
        is_safe, reason = self.is_safe_command(command)

        if not is_safe:
            logger.warning(f"Refused to execute unsafe command: {command[:100]} - {reason}")
            return ValidationResult(
                command=command,
                success=False,
                error=f"Command blocked for safety: {reason}",
            )

        # Parse the command for subprocess
        try:
            cmd_parts = shlex.split(command)
        except ValueError as e:
            return ValidationResult(
                command=command,
                success=False,
                error=f"Failed to parse command: {str(e)}",
            )

        # Log the execution attempt for audit
        execution_id = hashlib.sha256(
            f"{command}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        logger.info(
            f"Executing validation command [id={execution_id}]: {command[:100]}"
        )

        try:
            # Execute with shell=False for security
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,  # CRITICAL: Never use shell=True
                env=None,  # Use current environment
            )

            # Truncate output if too large
            stdout = result.stdout
            if len(stdout) > self.max_output_size:
                stdout = stdout[: self.max_output_size] + "\n... (output truncated)"

            stderr = result.stderr
            if len(stderr) > self.max_output_size:
                stderr = stderr[: self.max_output_size] + "\n... (output truncated)"

            success = result.returncode == 0

            logger.info(
                f"Validation command completed [id={execution_id}]: "
                f"exit_code={result.returncode}, success={success}"
            )

            return ValidationResult(
                command=command,
                success=success,
                output=stdout if stdout else None,
                error=stderr if stderr and not success else None,
            )

        except subprocess.TimeoutExpired:
            logger.warning(
                f"Validation command timed out [id={execution_id}] after {self.timeout}s"
            )
            return ValidationResult(
                command=command,
                success=False,
                error=f"Command timed out after {self.timeout} seconds",
            )
        except FileNotFoundError:
            logger.error(f"CLI tool not found for command [id={execution_id}]: {cmd_parts[0]}")
            return ValidationResult(
                command=command,
                success=False,
                error=f"CLI tool not found: {cmd_parts[0]}",
            )
        except Exception as e:
            logger.error(f"Unexpected error executing command [id={execution_id}]: {str(e)}")
            return ValidationResult(
                command=command,
                success=False,
                error=f"Execution error: {str(e)}",
            )

    def validate_attack_path(
        self, attack_path: dict[str, Any], dry_run: bool = False
    ) -> dict[str, Any]:
        """Validate an attack path and return results.

        Takes an attack path with PoC steps and validates each step
        using safe read-only commands.

        Args:
            attack_path: Dictionary containing attack path data with poc_steps
            dry_run: If True, only validate commands without executing

        Returns:
            Dictionary with:
            - path_id: The attack path ID
            - validation_status: "validated_exploitable", "validated_blocked", or "validation_failed"
            - validation_timestamp: When validation was performed
            - evidence: List of ValidationResult dictionaries
            - error: Error message if validation failed
        """
        path_id = attack_path.get("id") or attack_path.get("path_id")
        poc_steps = attack_path.get("poc_steps", [])

        logger.info(f"Validating attack path {path_id} with {len(poc_steps)} PoC steps")

        if not poc_steps:
            return {
                "path_id": path_id,
                "path_type": "attack",
                "validation_status": "validation_failed",
                "validation_timestamp": datetime.utcnow().isoformat(),
                "evidence": [],
                "error": "No PoC steps available for validation",
            }

        evidence: list[dict[str, Any]] = []
        all_successful = True
        any_blocked = False

        for step in poc_steps:
            command = step.get("command", "")

            if not command:
                continue

            # First, check if we need to transform to a safe command
            safe_command = self.transform_to_safe_command(step)

            if safe_command is None:
                # Try the original command if it's already safe
                is_safe, reason = self.is_safe_command(command)
                if is_safe:
                    safe_command = command
                else:
                    # Command cannot be safely validated
                    evidence.append(
                        {
                            "command": command,
                            "success": False,
                            "output": None,
                            "error": f"Cannot validate: {reason}",
                            "timestamp": datetime.utcnow().isoformat(),
                            "transformed": False,
                        }
                    )
                    any_blocked = True
                    continue

            if dry_run:
                # In dry run mode, just report what would be executed
                evidence.append(
                    {
                        "command": safe_command,
                        "success": True,
                        "output": "(dry run - command not executed)",
                        "error": None,
                        "timestamp": datetime.utcnow().isoformat(),
                        "dry_run": True,
                        "original_command": command if safe_command != command else None,
                    }
                )
            else:
                # Execute the safe command
                result = self.execute_safe_command(safe_command)
                evidence_entry = result.to_dict()
                evidence_entry["original_command"] = (
                    command if safe_command != command else None
                )
                evidence_entry["transformed"] = safe_command != command
                evidence.append(evidence_entry)

                if not result.success:
                    all_successful = False

        # Determine validation status
        if not evidence:
            validation_status = "validation_failed"
        elif dry_run:
            validation_status = "pending"
        elif all_successful:
            validation_status = "validated_exploitable"
        elif any_blocked:
            validation_status = "validated_blocked"
        else:
            validation_status = "validation_failed"

        return {
            "path_id": path_id,
            "path_type": "attack",
            "validation_status": validation_status,
            "validation_timestamp": datetime.utcnow().isoformat(),
            "evidence": evidence,
            "error": None,
        }

    def validate_privesc_path(
        self, privesc_path: dict[str, Any], dry_run: bool = False
    ) -> dict[str, Any]:
        """Validate a privilege escalation path.

        Takes a privilege escalation path with PoC commands and validates
        using safe read-only commands.

        Args:
            privesc_path: Dictionary containing privesc path data with poc_commands
            dry_run: If True, only validate commands without executing

        Returns:
            Dictionary with validation results
        """
        path_id = privesc_path.get("id") or privesc_path.get("path_id")
        poc_commands = privesc_path.get("poc_commands", [])

        logger.info(
            f"Validating privesc path {path_id} with {len(poc_commands)} PoC commands"
        )

        if not poc_commands:
            return {
                "path_id": path_id,
                "path_type": "privesc",
                "validation_status": "validation_failed",
                "validation_timestamp": datetime.utcnow().isoformat(),
                "evidence": [],
                "error": "No PoC commands available for validation",
            }

        evidence: list[dict[str, Any]] = []
        all_successful = True
        any_blocked = False

        for poc_cmd in poc_commands:
            # poc_commands can be a dict with 'command' key or just a string
            if isinstance(poc_cmd, dict):
                command = poc_cmd.get("command", "")
            else:
                command = str(poc_cmd)

            if not command:
                continue

            # Create a step dict for transformation
            step = {"command": command}

            # Transform to safe command
            safe_command = self.transform_to_safe_command(step)

            if safe_command is None:
                is_safe, reason = self.is_safe_command(command)
                if is_safe:
                    safe_command = command
                else:
                    evidence.append(
                        {
                            "command": command,
                            "success": False,
                            "output": None,
                            "error": f"Cannot validate: {reason}",
                            "timestamp": datetime.utcnow().isoformat(),
                            "transformed": False,
                        }
                    )
                    any_blocked = True
                    continue

            if dry_run:
                evidence.append(
                    {
                        "command": safe_command,
                        "success": True,
                        "output": "(dry run - command not executed)",
                        "error": None,
                        "timestamp": datetime.utcnow().isoformat(),
                        "dry_run": True,
                        "original_command": command if safe_command != command else None,
                    }
                )
            else:
                result = self.execute_safe_command(safe_command)
                evidence_entry = result.to_dict()
                evidence_entry["original_command"] = (
                    command if safe_command != command else None
                )
                evidence_entry["transformed"] = safe_command != command
                evidence.append(evidence_entry)

                if not result.success:
                    all_successful = False

        # Determine validation status
        if not evidence:
            validation_status = "validation_failed"
        elif dry_run:
            validation_status = "pending"
        elif all_successful:
            validation_status = "validated_exploitable"
        elif any_blocked:
            validation_status = "validated_blocked"
        else:
            validation_status = "validation_failed"

        return {
            "path_id": path_id,
            "path_type": "privesc",
            "validation_status": validation_status,
            "validation_timestamp": datetime.utcnow().isoformat(),
            "evidence": evidence,
            "error": None,
        }

    def batch_validate(
        self,
        paths: list[dict[str, Any]],
        path_type: str = "attack",
        dry_run: bool = False,
    ) -> list[dict[str, Any]]:
        """Batch validate multiple paths.

        Args:
            paths: List of path dictionaries to validate
            path_type: Type of paths ("attack" or "privesc")
            dry_run: If True, only validate commands without executing

        Returns:
            List of validation results for each path
        """
        results: list[dict[str, Any]] = []

        for path in paths:
            if path_type == "attack":
                result = self.validate_attack_path(path, dry_run=dry_run)
            else:
                result = self.validate_privesc_path(path, dry_run=dry_run)

            results.append(result)

        return results


# Module-level convenience function
def validate_command_safety(command: str) -> tuple[bool, str]:
    """Quick check if a command is safe to execute.

    Convenience function that creates a temporary validator instance.

    Args:
        command: The command to check

    Returns:
        Tuple of (is_safe, reason)
    """
    validator = PoCValidator()
    return validator.is_safe_command(command)
