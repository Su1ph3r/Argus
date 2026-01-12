"""Credential verification router for cloud provider permissions."""

import logging
import os
import sys
from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models.database import CredentialStatusCache, get_db

# Import permission requirements - try local first, then scripts directory
try:
    from permission_requirements import (
        AWS_MANAGED_POLICIES,
        AWS_TOOLS,
        AZURE_TOOLS,
        GCP_TOOLS,
        KUBERNETES_TOOLS,
        PROWLER_ADDITIONS_POLICY,
        get_tool_requirements,
    )

    REQUIREMENTS_AVAILABLE = True
except ImportError:
    # Try scripts directory as fallback
    scripts_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts"
    )
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    try:
        from permission_requirements import (
            AWS_MANAGED_POLICIES,
            AWS_TOOLS,
            AZURE_TOOLS,
            GCP_TOOLS,
            KUBERNETES_TOOLS,
            PROWLER_ADDITIONS_POLICY,
            get_tool_requirements,
        )

        REQUIREMENTS_AVAILABLE = True
    except ImportError:
        REQUIREMENTS_AVAILABLE = False
        AWS_TOOLS = {}
        AZURE_TOOLS = {}
        GCP_TOOLS = {}
        KUBERNETES_TOOLS = {}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])


class Provider(str, Enum):
    """Supported cloud providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


class AWSCredentials(BaseModel):
    """AWS credentials input."""

    access_key_id: str = Field(..., description="AWS Access Key ID")
    secret_access_key: str = Field(..., description="AWS Secret Access Key")
    session_token: str | None = Field(
        None, description="Optional session token for temporary credentials"
    )
    region: str = Field("us-east-1", description="Default AWS region")


class AzureCredentials(BaseModel):
    """Azure credentials input."""

    tenant_id: str = Field(..., description="Azure Tenant ID")
    client_id: str = Field(..., description="Azure Client/Application ID")
    client_secret: str = Field(..., description="Azure Client Secret")
    subscription_id: str | None = Field(None, description="Azure Subscription ID")


class GCPCredentials(BaseModel):
    """GCP credentials input."""

    project_id: str = Field(..., description="GCP Project ID")
    credentials_json: str = Field(..., description="Service account JSON key (paste full JSON)")


class KubernetesCredentials(BaseModel):
    """Kubernetes credentials input."""

    kubeconfig: str = Field(..., description="Kubeconfig file content (paste full YAML)")
    context: str | None = Field(None, description="Specific context to use")


class VerificationRequest(BaseModel):
    """Request to verify credentials."""

    provider: Provider
    aws: AWSCredentials | None = None
    azure: AzureCredentials | None = None
    gcp: GCPCredentials | None = None
    kubernetes: KubernetesCredentials | None = None


class VerificationResult(BaseModel):
    """Result of credential verification."""

    success: bool
    provider: str
    identity: str | None = None
    account_info: str | None = None
    permissions_checked: list[str] = Field(default_factory=list)
    permissions_available: list[str] = Field(default_factory=list)
    permissions_missing: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    raw_output: str = ""


def verify_aws_credentials(creds: AWSCredentials) -> VerificationResult:
    """Verify AWS credentials and check permissions."""
    result = VerificationResult(success=False, provider="aws", raw_output="")
    output_lines = []

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        result.errors.append("boto3 not installed")
        output_lines.append("[ERROR] boto3 library not installed")
        result.raw_output = "\n".join(output_lines)
        return result

    try:
        output_lines.append("=" * 60)
        output_lines.append("AWS CREDENTIAL VERIFICATION")
        output_lines.append("=" * 60)
        output_lines.append("")

        # Create session with provided credentials
        session = boto3.Session(
            aws_access_key_id=creds.access_key_id,
            aws_secret_access_key=creds.secret_access_key,
            aws_session_token=creds.session_token,
            region_name=creds.region,
        )

        # Get caller identity
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        result.identity = identity.get("Arn", "")
        result.account_info = f"Account: {identity.get('Account', 'Unknown')}"

        output_lines.append("[SUCCESS] Credentials are valid!")
        output_lines.append("")
        output_lines.append("IDENTITY INFORMATION:")
        output_lines.append(f"  ARN:     {identity.get('Arn', 'N/A')}")
        output_lines.append(f"  Account: {identity.get('Account', 'N/A')}")
        output_lines.append(f"  User ID: {identity.get('UserId', 'N/A')}")
        output_lines.append("")

        # Check common permissions for security tools
        permissions_to_check = [
            ("iam", "list_users", "iam:ListUsers"),
            ("iam", "list_roles", "iam:ListRoles"),
            ("iam", "list_policies", "iam:ListPolicies"),
            ("s3", "list_buckets", "s3:ListBuckets"),
            ("ec2", "describe_instances", "ec2:DescribeInstances"),
            ("ec2", "describe_security_groups", "ec2:DescribeSecurityGroups"),
            ("lambda", "list_functions", "lambda:ListFunctions"),
            ("rds", "describe_db_instances", "rds:DescribeDBInstances"),
            ("secretsmanager", "list_secrets", "secretsmanager:ListSecrets"),
            ("cloudtrail", "describe_trails", "cloudtrail:DescribeTrails"),
        ]

        output_lines.append("PERMISSION CHECKS:")
        output_lines.append("-" * 40)

        for service, operation, permission in permissions_to_check:
            result.permissions_checked.append(permission)
            try:
                client = session.client(service, region_name=creds.region)
                method = getattr(client, operation)
                method()
                result.permissions_available.append(permission)
                output_lines.append(f"  [OK]   {permission}")
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation", "AccessDeniedException"]:
                    result.permissions_missing.append(permission)
                    output_lines.append(f"  [DENY] {permission}")
                else:
                    # Other errors (region not available, service not enabled, etc.)
                    result.permissions_available.append(permission)
                    output_lines.append(f"  [OK]   {permission} (service responded)")
            except Exception:
                result.permissions_available.append(permission)
                output_lines.append(f"  [OK]   {permission} (service available)")

        output_lines.append("")
        output_lines.append("SUMMARY:")
        output_lines.append(
            f"  Permissions Available: {len(result.permissions_available)}/{len(result.permissions_checked)}"
        )
        output_lines.append(
            f"  Permissions Missing:   {len(result.permissions_missing)}/{len(result.permissions_checked)}"
        )
        output_lines.append("")

        # Determine overall success
        result.success = len(result.permissions_available) > 0

        if result.success:
            output_lines.append("[RESULT] Credentials verified successfully!")
            if result.permissions_missing:
                output_lines.append(
                    f"         Note: {len(result.permissions_missing)} permissions are restricted."
                )
        else:
            output_lines.append("[RESULT] Credentials have no usable permissions.")

    except NoCredentialsError:
        result.errors.append("Invalid credentials format")
        output_lines.append("[ERROR] Invalid credentials format")
    except ClientError as e:
        error_msg = str(e)
        result.errors.append(error_msg)
        output_lines.append(f"[ERROR] AWS API Error: {error_msg}")
    except Exception as e:
        result.errors.append(str(e))
        output_lines.append(f"[ERROR] {str(e)}")

    result.raw_output = "\n".join(output_lines)
    return result


def verify_azure_credentials(creds: AzureCredentials) -> VerificationResult:
    """Verify Azure credentials."""
    result = VerificationResult(success=False, provider="azure", raw_output="")
    output_lines = []

    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import SubscriptionClient

        output_lines.append("=" * 60)
        output_lines.append("AZURE CREDENTIAL VERIFICATION")
        output_lines.append("=" * 60)
        output_lines.append("")

        # Create credential object
        credential = ClientSecretCredential(
            tenant_id=creds.tenant_id, client_id=creds.client_id, client_secret=creds.client_secret
        )

        # List subscriptions to verify access
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        result.success = True
        result.identity = f"App: {creds.client_id}"
        result.account_info = f"Tenant: {creds.tenant_id}"

        output_lines.append("[SUCCESS] Credentials are valid!")
        output_lines.append("")
        output_lines.append("IDENTITY INFORMATION:")
        output_lines.append(f"  Tenant ID:  {creds.tenant_id}")
        output_lines.append(f"  Client ID:  {creds.client_id}")
        output_lines.append("")
        output_lines.append("ACCESSIBLE SUBSCRIPTIONS:")

        for sub in subscriptions:
            output_lines.append(f"  - {sub.display_name} ({sub.subscription_id})")
            result.permissions_available.append(f"Subscription: {sub.display_name}")

        if not subscriptions:
            output_lines.append("  (No subscriptions accessible)")

        output_lines.append("")
        output_lines.append(f"[RESULT] Access verified to {len(subscriptions)} subscription(s)")

    except ImportError:
        result.errors.append("azure-identity and azure-mgmt-resource not installed")
        output_lines.append("[ERROR] Azure SDK not installed")
        output_lines.append("        Install with: pip install azure-identity azure-mgmt-resource")
    except Exception as e:
        result.errors.append(str(e))
        output_lines.append(f"[ERROR] {str(e)}")

    result.raw_output = "\n".join(output_lines)
    return result


def verify_gcp_credentials(creds: GCPCredentials) -> VerificationResult:
    """Verify GCP credentials."""
    import json
    import tempfile

    result = VerificationResult(success=False, provider="gcp", raw_output="")
    output_lines = []

    try:
        from google.cloud import resourcemanager_v3
        from google.oauth2 import service_account

        output_lines.append("=" * 60)
        output_lines.append("GCP CREDENTIAL VERIFICATION")
        output_lines.append("=" * 60)
        output_lines.append("")

        # Parse the JSON credentials
        try:
            creds_dict = json.loads(creds.credentials_json)
        except json.JSONDecodeError:
            result.errors.append("Invalid JSON format for credentials")
            output_lines.append("[ERROR] Invalid JSON format for service account key")
            result.raw_output = "\n".join(output_lines)
            return result

        # Write to temp file for SDK
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(creds_dict, f)
            temp_path = f.name

        try:
            # Create credentials
            credentials = service_account.Credentials.from_service_account_file(temp_path)

            result.success = True
            result.identity = creds_dict.get("client_email", "Unknown")
            result.account_info = f"Project: {creds.project_id}"

            output_lines.append("[SUCCESS] Credentials are valid!")
            output_lines.append("")
            output_lines.append("SERVICE ACCOUNT INFORMATION:")
            output_lines.append(f"  Email:      {creds_dict.get('client_email', 'N/A')}")
            output_lines.append(f"  Project:    {creds_dict.get('project_id', 'N/A')}")
            output_lines.append(f"  Key ID:     {creds_dict.get('private_key_id', 'N/A')[:16]}...")
            output_lines.append("")
            output_lines.append("[RESULT] Service account credentials verified")

        finally:
            os.unlink(temp_path)

    except ImportError:
        result.errors.append("google-cloud-resource-manager not installed")
        output_lines.append("[ERROR] GCP SDK not installed")
        output_lines.append("        Install with: pip install google-cloud-resource-manager")
    except Exception as e:
        result.errors.append(str(e))
        output_lines.append(f"[ERROR] {str(e)}")

    result.raw_output = "\n".join(output_lines)
    return result


def verify_kubernetes_credentials(creds: KubernetesCredentials) -> VerificationResult:
    """Verify Kubernetes credentials."""
    import tempfile

    result = VerificationResult(success=False, provider="kubernetes", raw_output="")
    output_lines = []

    try:
        from kubernetes import client, config

        output_lines.append("=" * 60)
        output_lines.append("KUBERNETES CREDENTIAL VERIFICATION")
        output_lines.append("=" * 60)
        output_lines.append("")

        # Write kubeconfig to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(creds.kubeconfig)
            temp_path = f.name

        try:
            # Load the config
            config.load_kube_config(config_file=temp_path, context=creds.context)

            # Try to get cluster info
            v1 = client.CoreV1Api()
            version_api = client.VersionApi()

            # Get version
            version = version_api.get_code()

            result.success = True
            result.identity = f"Context: {creds.context or 'default'}"
            result.account_info = f"Kubernetes {version.git_version}"

            output_lines.append("[SUCCESS] Kubeconfig is valid!")
            output_lines.append("")
            output_lines.append("CLUSTER INFORMATION:")
            output_lines.append(f"  Version:  {version.git_version}")
            output_lines.append(f"  Platform: {version.platform}")
            output_lines.append("")

            # Try to list namespaces
            try:
                namespaces = v1.list_namespace()
                output_lines.append("ACCESSIBLE NAMESPACES:")
                for ns in namespaces.items[:10]:
                    output_lines.append(f"  - {ns.metadata.name}")
                    result.permissions_available.append(f"Namespace: {ns.metadata.name}")
                if len(namespaces.items) > 10:
                    output_lines.append(f"  ... and {len(namespaces.items) - 10} more")
            except Exception as e:
                output_lines.append(f"  (Cannot list namespaces: {str(e)[:50]})")
                result.permissions_missing.append("list namespaces")

            output_lines.append("")
            output_lines.append("[RESULT] Kubernetes cluster accessible")

        finally:
            os.unlink(temp_path)

    except ImportError:
        result.errors.append("kubernetes client not installed")
        output_lines.append("[ERROR] Kubernetes Python client not installed")
        output_lines.append("        Install with: pip install kubernetes")
    except Exception as e:
        result.errors.append(str(e))
        output_lines.append(f"[ERROR] {str(e)}")

    result.raw_output = "\n".join(output_lines)
    return result


@router.post("/verify", response_model=VerificationResult)
async def verify_credentials(request: VerificationRequest) -> VerificationResult:
    """
    Verify cloud provider credentials.

    Accepts credentials for AWS, Azure, GCP, or Kubernetes and validates them
    by attempting to authenticate and list basic resources.
    """
    if request.provider == Provider.AWS:
        if not request.aws:
            raise HTTPException(status_code=400, detail="AWS credentials required")
        return verify_aws_credentials(request.aws)

    elif request.provider == Provider.AZURE:
        if not request.azure:
            raise HTTPException(status_code=400, detail="Azure credentials required")
        return verify_azure_credentials(request.azure)

    elif request.provider == Provider.GCP:
        if not request.gcp:
            raise HTTPException(status_code=400, detail="GCP credentials required")
        return verify_gcp_credentials(request.gcp)

    elif request.provider == Provider.KUBERNETES:
        if not request.kubernetes:
            raise HTTPException(status_code=400, detail="Kubernetes credentials required")
        return verify_kubernetes_credentials(request.kubernetes)

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {request.provider}")


@router.get("/providers")
async def list_providers() -> dict[str, Any]:
    """List all supported cloud providers and required fields."""
    return {
        "providers": [
            {
                "id": "aws",
                "name": "Amazon Web Services",
                "fields": [
                    {
                        "name": "access_key_id",
                        "label": "Access Key ID",
                        "type": "text",
                        "required": True,
                    },
                    {
                        "name": "secret_access_key",
                        "label": "Secret Access Key",
                        "type": "password",
                        "required": True,
                    },
                    {
                        "name": "session_token",
                        "label": "Session Token",
                        "type": "password",
                        "required": False,
                    },
                    {
                        "name": "region",
                        "label": "Region",
                        "type": "text",
                        "required": False,
                        "default": "us-east-1",
                    },
                ],
            },
            {
                "id": "azure",
                "name": "Microsoft Azure",
                "fields": [
                    {"name": "tenant_id", "label": "Tenant ID", "type": "text", "required": True},
                    {
                        "name": "client_id",
                        "label": "Client/App ID",
                        "type": "text",
                        "required": True,
                    },
                    {
                        "name": "client_secret",
                        "label": "Client Secret",
                        "type": "password",
                        "required": True,
                    },
                    {
                        "name": "subscription_id",
                        "label": "Subscription ID",
                        "type": "text",
                        "required": False,
                    },
                ],
            },
            {
                "id": "gcp",
                "name": "Google Cloud Platform",
                "fields": [
                    {"name": "project_id", "label": "Project ID", "type": "text", "required": True},
                    {
                        "name": "credentials_json",
                        "label": "Service Account JSON",
                        "type": "textarea",
                        "required": True,
                    },
                ],
            },
            {
                "id": "kubernetes",
                "name": "Kubernetes",
                "fields": [
                    {
                        "name": "kubeconfig",
                        "label": "Kubeconfig YAML",
                        "type": "textarea",
                        "required": True,
                    },
                    {"name": "context", "label": "Context Name", "type": "text", "required": False},
                ],
            },
        ]
    }


# ============================================================================
# Tool Readiness Models
# ============================================================================


class ToolReadiness(BaseModel):
    """Readiness status for a single tool."""

    tool_name: str
    tool_display_name: str
    ready: bool
    status: str = Field(description="ready, partial, or failed")
    permissions_ok: list[str] = []
    permissions_missing: list[str] = []
    remediation: str | None = None
    note: str | None = None


class EnhancedVerificationResult(BaseModel):
    """Enhanced verification result with tool readiness."""

    success: bool
    provider: str
    identity: str | None = None
    account_info: str | None = None
    overall_status: str = Field(description="ready, partial, or failed")
    tools: list[ToolReadiness] = []
    tools_ready: list[str] = []
    tools_partial: list[str] = []
    tools_failed: list[str] = []
    errors: list[str] = []
    raw_output: str = ""


class CredentialStatusSummary(BaseModel):
    """Summary of credential status for all providers."""

    aws: str = "unknown"
    azure: str = "unknown"
    gcp: str = "unknown"
    kubernetes: str = "unknown"


class AllCredentialStatus(BaseModel):
    """Full credential status for all providers."""

    summary: CredentialStatusSummary
    details: dict[str, Any] = {}


def check_aws_tool_permissions(
    session, region: str, tool_name: str, tool_config: dict
) -> ToolReadiness:
    """Check permissions for a specific AWS tool."""
    from botocore.exceptions import ClientError

    result = ToolReadiness(
        tool_name=tool_name,
        tool_display_name=tool_config.get("name", tool_name),
        ready=False,
        status="failed",
    )

    required_actions = tool_config.get("required_actions", [])
    if not required_actions:
        # If no specific actions to check, assume ready if basic auth worked
        result.ready = True
        result.status = "ready"
        result.note = "Uses managed policies only"
        return result

    # Sample check a few key permissions
    sample_checks = {
        "iam:ListUsers": ("iam", "list_users"),
        "iam:ListRoles": ("iam", "list_roles"),
        "s3:ListBuckets": ("s3", "list_buckets"),
        "ec2:DescribeInstances": ("ec2", "describe_instances"),
        "cloudtrail:DescribeTrails": ("cloudtrail", "describe_trails"),
        "ec2:GetEbsEncryptionByDefault": ("ec2", "get_ebs_encryption_by_default"),
        "lambda:ListFunctions": ("lambda", "list_functions"),
    }

    checked = 0
    passed = 0

    for action in required_actions[:5]:  # Check first 5 actions
        if action in sample_checks:
            service, method_name = sample_checks[action]
            try:
                client = session.client(service, region_name=region)
                method = getattr(client, method_name, None)
                if method:
                    method()
                    result.permissions_ok.append(action)
                    passed += 1
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation", "AccessDeniedException"]:
                    result.permissions_missing.append(action)
                else:
                    result.permissions_ok.append(action)
                    passed += 1
            except Exception:
                result.permissions_ok.append(action)
                passed += 1
            checked += 1

    if checked == 0 or passed == checked:
        result.ready = True
        result.status = "ready"
    elif passed > 0:
        result.ready = True
        result.status = "partial"
        result.remediation = f"Missing {checked - passed} permissions for full {tool_config.get('name', tool_name)} coverage"
    else:
        result.status = "failed"
        result.remediation = (
            f"Attach {tool_config.get('required_managed_policies', ['SecurityAudit'])} policy"
        )

    return result


def verify_aws_enhanced(creds: "AWSCredentials") -> EnhancedVerificationResult:
    """Enhanced AWS credential verification with tool readiness."""
    result = EnhancedVerificationResult(
        success=False, provider="aws", overall_status="failed", raw_output=""
    )
    output_lines = []

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        result.errors.append("boto3 not installed")
        result.raw_output = "[ERROR] boto3 library not installed"
        return result

    try:
        output_lines.append("=" * 60)
        output_lines.append("AWS CREDENTIAL VERIFICATION (Enhanced)")
        output_lines.append("=" * 60)
        output_lines.append("")

        # Create session
        session = boto3.Session(
            aws_access_key_id=creds.access_key_id,
            aws_secret_access_key=creds.secret_access_key,
            aws_session_token=creds.session_token,
            region_name=creds.region,
        )

        # Get caller identity
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        result.identity = identity.get("Arn", "")
        result.account_info = f"Account: {identity.get('Account', 'Unknown')}"
        result.success = True

        output_lines.append("[SUCCESS] Credentials are valid!")
        output_lines.append("")
        output_lines.append("IDENTITY INFORMATION:")
        output_lines.append(f"  ARN:     {identity.get('Arn', 'N/A')}")
        output_lines.append(f"  Account: {identity.get('Account', 'N/A')}")
        output_lines.append("")

        # Check tool readiness
        output_lines.append("TOOL READINESS:")
        output_lines.append("-" * 40)

        for tool_name, tool_config in AWS_TOOLS.items():
            tool_result = check_aws_tool_permissions(session, creds.region, tool_name, tool_config)
            result.tools.append(tool_result)

            if tool_result.status == "ready":
                result.tools_ready.append(tool_name)
                output_lines.append(f"  [READY]   {tool_config.get('name', tool_name)}")
            elif tool_result.status == "partial":
                result.tools_partial.append(tool_name)
                output_lines.append(f"  [PARTIAL] {tool_config.get('name', tool_name)}")
            else:
                result.tools_failed.append(tool_name)
                output_lines.append(f"  [FAILED]  {tool_config.get('name', tool_name)}")

        output_lines.append("")

        # Determine overall status
        if result.tools_ready and not result.tools_failed:
            result.overall_status = "ready"
        elif result.tools_ready or result.tools_partial:
            result.overall_status = "partial"
        else:
            result.overall_status = "failed"

        output_lines.append(f"OVERALL STATUS: {result.overall_status.upper()}")
        output_lines.append(f"  Tools Ready:   {len(result.tools_ready)}")
        output_lines.append(f"  Tools Partial: {len(result.tools_partial)}")
        output_lines.append(f"  Tools Failed:  {len(result.tools_failed)}")

    except NoCredentialsError:
        result.errors.append("Invalid credentials format")
        output_lines.append("[ERROR] Invalid credentials format")
    except ClientError as e:
        result.errors.append(str(e))
        output_lines.append(f"[ERROR] AWS API Error: {str(e)}")
    except Exception as e:
        result.errors.append(str(e))
        output_lines.append(f"[ERROR] {str(e)}")

    result.raw_output = "\n".join(output_lines)
    return result


@router.post("/verify-enhanced", response_model=EnhancedVerificationResult)
async def verify_credentials_enhanced(
    request: VerificationRequest, db: Session = Depends(get_db)
) -> EnhancedVerificationResult:
    """
    Enhanced credential verification with tool-level readiness.

    Returns detailed status for each security tool, indicating whether
    credentials have sufficient permissions to run the tool.
    """
    result: EnhancedVerificationResult

    if request.provider == Provider.AWS:
        if not request.aws:
            raise HTTPException(status_code=400, detail="AWS credentials required")
        result = verify_aws_enhanced(request.aws)

    elif request.provider == Provider.AZURE:
        if not request.azure:
            raise HTTPException(status_code=400, detail="Azure credentials required")
        # Use basic verification for now, enhanced Azure verification can be added later
        basic_result = verify_azure_credentials(request.azure)
        result = EnhancedVerificationResult(
            success=basic_result.success,
            provider="azure",
            identity=basic_result.identity,
            account_info=basic_result.account_info,
            overall_status="ready" if basic_result.success else "failed",
            tools_ready=list(AZURE_TOOLS.keys()) if basic_result.success else [],
            errors=basic_result.errors,
            raw_output=basic_result.raw_output,
        )
        for tool_name, tool_config in AZURE_TOOLS.items():
            result.tools.append(
                ToolReadiness(
                    tool_name=tool_name,
                    tool_display_name=tool_config.get("name", tool_name),
                    ready=basic_result.success,
                    status="ready" if basic_result.success else "failed",
                )
            )

    elif request.provider == Provider.GCP:
        if not request.gcp:
            raise HTTPException(status_code=400, detail="GCP credentials required")
        basic_result = verify_gcp_credentials(request.gcp)
        result = EnhancedVerificationResult(
            success=basic_result.success,
            provider="gcp",
            identity=basic_result.identity,
            account_info=basic_result.account_info,
            overall_status="ready" if basic_result.success else "failed",
            tools_ready=list(GCP_TOOLS.keys()) if basic_result.success else [],
            errors=basic_result.errors,
            raw_output=basic_result.raw_output,
        )
        for tool_name, tool_config in GCP_TOOLS.items():
            result.tools.append(
                ToolReadiness(
                    tool_name=tool_name,
                    tool_display_name=tool_config.get("name", tool_name),
                    ready=basic_result.success,
                    status="ready" if basic_result.success else "failed",
                )
            )

    elif request.provider == Provider.KUBERNETES:
        if not request.kubernetes:
            raise HTTPException(status_code=400, detail="Kubernetes credentials required")
        basic_result = verify_kubernetes_credentials(request.kubernetes)
        result = EnhancedVerificationResult(
            success=basic_result.success,
            provider="kubernetes",
            identity=basic_result.identity,
            account_info=basic_result.account_info,
            overall_status="ready" if basic_result.success else "failed",
            tools_ready=list(KUBERNETES_TOOLS.keys()) if basic_result.success else [],
            errors=basic_result.errors,
            raw_output=basic_result.raw_output,
        )
        for tool_name, tool_config in KUBERNETES_TOOLS.items():
            result.tools.append(
                ToolReadiness(
                    tool_name=tool_name,
                    tool_display_name=tool_config.get("name", tool_name),
                    ready=basic_result.success,
                    status="ready" if basic_result.success else "failed",
                    note=tool_config.get("note"),
                )
            )

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {request.provider}")

    # Cache the result
    try:
        cache_entry = (
            db.query(CredentialStatusCache)
            .filter(CredentialStatusCache.provider == request.provider.value)
            .first()
        )

        if cache_entry:
            cache_entry.status = result.overall_status
            cache_entry.identity = result.identity
            cache_entry.account_info = result.account_info
            cache_entry.tools_ready = result.tools_ready
            cache_entry.tools_partial = result.tools_partial
            cache_entry.tools_failed = result.tools_failed
            cache_entry.last_verified = datetime.utcnow()
            cache_entry.verification_error = result.errors[0] if result.errors else None
            cache_entry.updated_at = datetime.utcnow()
        else:
            cache_entry = CredentialStatusCache(
                provider=request.provider.value,
                status=result.overall_status,
                identity=result.identity,
                account_info=result.account_info,
                tools_ready=result.tools_ready,
                tools_partial=result.tools_partial,
                tools_failed=result.tools_failed,
                last_verified=datetime.utcnow(),
                verification_error=result.errors[0] if result.errors else None,
            )
            db.add(cache_entry)

        db.commit()
    except Exception as e:
        logger.warning(f"Failed to cache credential status: {e}")

    return result


@router.get("/status", response_model=AllCredentialStatus)
async def get_credential_status(db: Session = Depends(get_db)) -> AllCredentialStatus:
    """
    Get cached credential status for all providers.

    Returns the most recent verification status without re-verifying credentials.
    """
    cache_entries = db.query(CredentialStatusCache).all()

    summary = CredentialStatusSummary()
    details = {}

    for entry in cache_entries:
        setattr(summary, entry.provider, entry.status)
        details[entry.provider] = {
            "status": entry.status,
            "identity": entry.identity,
            "account_info": entry.account_info,
            "tools_ready": entry.tools_ready or [],
            "tools_partial": entry.tools_partial or [],
            "tools_failed": entry.tools_failed or [],
            "last_verified": entry.last_verified.isoformat() if entry.last_verified else None,
            "error": entry.verification_error,
        }

    return AllCredentialStatus(summary=summary, details=details)


@router.get("/requirements")
async def get_tool_requirements_endpoint() -> dict[str, Any]:
    """
    Get permission requirements for all tools by provider.

    Returns the required permissions, roles, and policies for each security tool.
    """
    if not REQUIREMENTS_AVAILABLE:
        raise HTTPException(status_code=500, detail="Permission requirements module not available")

    return {
        "aws": {
            tool_name: {
                "name": config.get("name"),
                "description": config.get("description"),
                "required_managed_policies": config.get("required_managed_policies", []),
                "sample_actions": config.get("required_actions", [])[:5],
            }
            for tool_name, config in AWS_TOOLS.items()
        },
        "azure": {
            tool_name: {
                "name": config.get("name"),
                "description": config.get("description"),
                "required_roles": config.get("required_roles", []),
                "required_graph_permissions": config.get("required_graph_permissions", []),
            }
            for tool_name, config in AZURE_TOOLS.items()
        },
        "gcp": {
            tool_name: {
                "name": config.get("name"),
                "description": config.get("description"),
                "required_roles": config.get("required_roles", []),
                "sample_permissions": config.get("required_permissions", [])[:5],
            }
            for tool_name, config in GCP_TOOLS.items()
        },
        "kubernetes": {
            tool_name: {
                "name": config.get("name"),
                "description": config.get("description"),
                "cluster_wide": config.get("cluster_wide", False),
                "host_access_required": config.get("host_access_required", False),
                "note": config.get("note"),
            }
            for tool_name, config in KUBERNETES_TOOLS.items()
        },
    }
