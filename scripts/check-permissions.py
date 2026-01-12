#!/usr/bin/env python3
"""
Nubicustos - Permission Validator

Pre-flight tool to validate that cloud credentials have the required
permissions and roles for each security scanning tool.

Usage:
    python check-permissions.py --provider aws
    python check-permissions.py --provider all --output report.md --remediation
"""

import argparse
import configparser
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Import permission requirements
from permission_requirements import (
    AWS_MANAGED_POLICIES,
    AWS_TOOLS,
    AZURE_BUILTIN_ROLES,
    AZURE_TOOLS,
    CLOUDSPLOIT_GCP_CUSTOM_ROLE,
    GCP_PREDEFINED_ROLES,
    GCP_TOOLS,
    KUBERNETES_TOOLS,
    KUBESCAPE_CLUSTER_ROLE,
    PROWLER_ADDITIONS_POLICY,
    TRIVY_CLUSTER_ROLE,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class PermissionResult:
    """Result of a permission check for a single tool."""

    tool_name: str
    tool_display_name: str
    passed: bool
    missing_policies: list[str] = field(default_factory=list)
    missing_permissions: list[str] = field(default_factory=list)
    missing_roles: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ProviderResult:
    """Results for all tools in a provider."""

    provider: str
    account_info: str
    tool_results: list[PermissionResult] = field(default_factory=list)
    connection_error: str | None = None


# =============================================================================
# Colors for Terminal Output
# =============================================================================


class Colors:
    """ANSI color codes for terminal output."""

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    NC = "\033[0m"  # No Color

    @classmethod
    def disable(cls):
        """Disable colors for non-terminal output."""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.CYAN = ""
        cls.BOLD = ""
        cls.NC = ""


# =============================================================================
# Credential Loading
# =============================================================================


def get_project_dir() -> Path:
    """Get the project root directory."""
    script_dir = Path(__file__).parent
    return script_dir.parent


def load_aws_credentials(args) -> dict | None:
    """Load AWS credentials from file or CLI args."""
    # CLI args take precedence
    if args.aws_access_key and args.aws_secret_key:
        return {
            "aws_access_key_id": args.aws_access_key,
            "aws_secret_access_key": args.aws_secret_key,
            "region_name": args.aws_region or "us-east-1",
        }

    # Check for profile
    if args.aws_profile:
        return {"profile_name": args.aws_profile}

    # Load from credentials directory
    creds_file = get_project_dir() / "credentials" / "aws" / "credentials"
    config_file = get_project_dir() / "credentials" / "aws" / "config"

    if creds_file.exists():
        config = configparser.ConfigParser()
        config.read(creds_file)

        profile = "default"
        if profile in config:
            creds = {
                "aws_access_key_id": config[profile].get("aws_access_key_id"),
                "aws_secret_access_key": config[profile].get("aws_secret_access_key"),
            }

            # Load region from config file
            if config_file.exists():
                config.read(config_file)
                if profile in config:
                    creds["region_name"] = config[profile].get("region", "us-east-1")

            return creds

    return None


def load_azure_credentials(args) -> dict | None:
    """Load Azure credentials from file or CLI args."""
    # CLI args take precedence
    if args.azure_tenant_id and args.azure_client_id and args.azure_client_secret:
        return {
            "tenant_id": args.azure_tenant_id,
            "client_id": args.azure_client_id,
            "client_secret": args.azure_client_secret,
            "subscription_id": args.azure_subscription_id,
            "object_id": getattr(args, "azure_object_id", None),
        }

    # Load from credentials directory
    creds_file = get_project_dir() / "credentials" / "azure" / "credentials.json"

    if creds_file.exists():
        try:
            with open(creds_file) as f:
                data = json.load(f)
                return {
                    "tenant_id": data.get("tenantId"),
                    "client_id": data.get("clientId"),
                    "client_secret": data.get("clientSecret"),
                    "subscription_id": data.get("subscriptionId"),
                    "object_id": data.get("objectId"),  # Optional field
                }
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in Azure credentials file: {e}")
            return None

    return None


def load_gcp_credentials(args) -> dict | None:
    """Load GCP credentials from file or CLI args."""
    # CLI args take precedence
    if args.gcp_credentials_file:
        if not os.path.exists(args.gcp_credentials_file):
            logger.error(f"GCP credentials file not found: {args.gcp_credentials_file}")
            return None
        return {
            "credentials_file": args.gcp_credentials_file,
            "project_id": args.gcp_project_id,
        }

    # Load from credentials directory
    creds_file = get_project_dir() / "credentials" / "gcp" / "credentials.json"

    if creds_file.exists():
        return {
            "credentials_file": str(creds_file),
            "project_id": args.gcp_project_id,
        }

    return None


def load_kubernetes_credentials(args) -> dict | None:
    """Load Kubernetes credentials from file or CLI args."""
    # CLI args take precedence
    if args.kubeconfig:
        return {
            "kubeconfig": args.kubeconfig,
            "context": args.kube_context,
        }

    # Load from kubeconfigs directory
    kubeconfig_file = get_project_dir() / "kubeconfigs" / "config"

    if kubeconfig_file.exists():
        return {
            "kubeconfig": str(kubeconfig_file),
            "context": args.kube_context,
        }

    return None


# =============================================================================
# AWS Permission Validation
# =============================================================================


def check_aws_permissions(credentials: dict, args) -> ProviderResult:
    """Check AWS permissions for all tools."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        return ProviderResult(
            provider="aws",
            account_info="",
            connection_error="boto3 not installed. Run: pip install boto3",
        )

    try:
        # Create session
        if "profile_name" in credentials:
            session = boto3.Session(profile_name=credentials["profile_name"])
        else:
            session = boto3.Session(**credentials)

        # Get account info
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        arn = identity["Arn"]

        # Determine if user or role
        iam = session.client("iam")

        # Extract user/role name from ARN
        if ":user/" in arn:
            principal_type = "user"
            principal_name = arn.split(":user/")[-1]
        elif ":role/" in arn:
            principal_type = "role"
            principal_name = arn.split(":role/")[-1].split("/")[-1]
        elif ":assumed-role/" in arn:
            principal_type = "assumed-role"
            principal_name = arn.split(":assumed-role/")[-1].split("/")[0]
        else:
            principal_type = "unknown"
            principal_name = arn

        account_info = f"Account: {account_id} | {principal_type}: {principal_name}"

        result = ProviderResult(provider="aws", account_info=account_info)

        # Check each tool
        for tool_key, tool_config in AWS_TOOLS.items():
            tool_result = check_aws_tool_permissions(
                iam,
                sts,
                session,
                tool_key,
                tool_config,
                principal_type,
                principal_name,
                arn,
            )
            result.tool_results.append(tool_result)

        return result

    except NoCredentialsError:
        return ProviderResult(
            provider="aws", account_info="", connection_error="No AWS credentials found"
        )
    except ClientError as e:
        return ProviderResult(
            provider="aws", account_info="", connection_error=f"AWS API error: {e}"
        )
    except Exception as e:
        return ProviderResult(provider="aws", account_info="", connection_error=f"Error: {e}")


def check_aws_tool_permissions(
    iam,
    sts,
    session,
    tool_key: str,
    tool_config: dict,
    principal_type: str,
    principal_name: str,
    arn: str,
) -> PermissionResult:
    """Check permissions for a specific AWS tool."""
    from botocore.exceptions import ClientError

    result = PermissionResult(
        tool_name=tool_key, tool_display_name=tool_config["name"], passed=True
    )

    # Get attached policies
    attached_policy_arns = set()

    try:
        if principal_type == "user":
            # Get user's attached policies
            paginator = iam.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=principal_name):
                for policy in page["AttachedPolicies"]:
                    attached_policy_arns.add(policy["PolicyArn"])

            # Get policies from groups
            groups_resp = iam.list_groups_for_user(UserName=principal_name)
            for group in groups_resp["Groups"]:
                group_paginator = iam.get_paginator("list_attached_group_policies")
                for page in group_paginator.paginate(GroupName=group["GroupName"]):
                    for policy in page["AttachedPolicies"]:
                        attached_policy_arns.add(policy["PolicyArn"])

        elif principal_type == "role" or principal_type == "assumed-role":
            # Get role's attached policies
            try:
                paginator = iam.get_paginator("list_attached_role_policies")
                for page in paginator.paginate(RoleName=principal_name):
                    for policy in page["AttachedPolicies"]:
                        attached_policy_arns.add(policy["PolicyArn"])
            except ClientError:
                result.notes.append(
                    "Could not list role policies (may lack iam:ListAttachedRolePolicies)"
                )

    except ClientError as e:
        result.errors.append(f"Error listing policies: {e}")

    # Check required managed policies
    for policy_name in tool_config.get("required_managed_policies", []):
        policy_arn = AWS_MANAGED_POLICIES.get(policy_name)
        if policy_arn and policy_arn not in attached_policy_arns:
            result.missing_policies.append(policy_name)
            result.passed = False

    # Simulate key permissions using IAM policy simulator
    try:
        actions_to_test = tool_config.get("required_actions", [])[:5]  # Test first 5
        if actions_to_test:
            sim_result = iam.simulate_principal_policy(
                PolicySourceArn=arn, ActionNames=actions_to_test, ResourceArns=["*"]
            )

            for eval_result in sim_result["EvaluationResults"]:
                if eval_result["EvalDecision"] != "allowed":
                    result.missing_permissions.append(eval_result["EvalActionName"])
                    result.passed = False

    except ClientError as e:
        # Policy simulation may not be available
        if "AccessDenied" in str(e):
            result.notes.append("Cannot simulate policies (lacks iam:SimulatePrincipalPolicy)")
        else:
            result.errors.append(f"Simulation error: {e}")

    return result


# =============================================================================
# Azure Permission Validation
# =============================================================================


def check_azure_permissions(credentials: dict, args) -> ProviderResult:
    """Check Azure permissions for all tools."""
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.mgmt.resource import SubscriptionClient
    except ImportError:
        return ProviderResult(
            provider="azure",
            account_info="",
            connection_error="Azure SDK not installed. Run: pip install azure-identity azure-mgmt-authorization azure-mgmt-resource",
        )

    try:
        credential = ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )

        subscription_id = credentials.get("subscription_id")

        if not subscription_id:
            # Try to get first subscription
            sub_client = SubscriptionClient(credential)
            subs = list(sub_client.subscriptions.list())
            if subs:
                subscription_id = subs[0].subscription_id
            else:
                return ProviderResult(
                    provider="azure",
                    account_info="",
                    connection_error="No subscriptions found",
                )

        account_info = f"Subscription: {subscription_id}"

        auth_client = AuthorizationManagementClient(credential, subscription_id)

        result = ProviderResult(provider="azure", account_info=account_info)

        # Get current principal's role assignments
        # Note: Azure role assignments use object_id, not client_id
        principal_id = credentials.get("object_id")

        if not principal_id:
            # Fall back to client_id with warning - this may not work correctly
            principal_id = credentials["client_id"]
            logger.warning(
                "Using client_id for role lookup. For accurate results, provide --azure-object-id or add 'objectId' to credentials file"
            )

        # List role assignments for this principal
        assigned_roles = set()
        role_lookup_warning = None
        try:
            for assignment in auth_client.role_assignments.list_for_subscription():
                if assignment.principal_id == principal_id:
                    # Extract role name from role definition ID
                    role_def_id = assignment.role_definition_id
                    role_name = role_def_id.split("/")[-1]
                    assigned_roles.add(role_name)

            if not assigned_roles and not credentials.get("object_id"):
                role_lookup_warning = "No roles found. If using client_id, try providing the service principal's object_id instead"
        except Exception as e:
            result.connection_error = f"Error listing role assignments: {e}"
            return result

        # Check each tool
        for tool_key, tool_config in AZURE_TOOLS.items():
            tool_result = check_azure_tool_permissions(tool_key, tool_config, assigned_roles)
            # Add warning if role lookup may be incomplete
            if role_lookup_warning:
                tool_result.notes.append(role_lookup_warning)
            result.tool_results.append(tool_result)

        return result

    except Exception as e:
        return ProviderResult(provider="azure", account_info="", connection_error=f"Error: {e}")


def check_azure_tool_permissions(
    tool_key: str, tool_config: dict, assigned_roles: set
) -> PermissionResult:
    """Check permissions for a specific Azure tool."""
    result = PermissionResult(
        tool_name=tool_key, tool_display_name=tool_config["name"], passed=True
    )

    # Check required roles
    for role_name in tool_config.get("required_roles", []):
        role_id = AZURE_BUILTIN_ROLES.get(role_name, role_name)
        if role_id not in assigned_roles and role_name not in assigned_roles:
            result.missing_roles.append(role_name)
            result.passed = False

    # Note about Graph API permissions
    graph_perms = tool_config.get("required_graph_permissions", [])
    if graph_perms:
        result.notes.append(f"Requires Graph API permissions: {', '.join(graph_perms)}")
        result.notes.append("Graph permissions must be verified in Azure AD App Registration")

    return result


# =============================================================================
# GCP Permission Validation
# =============================================================================


def check_gcp_permissions(credentials: dict, args) -> ProviderResult:
    """Check GCP permissions for all tools."""
    try:
        from google.cloud import resourcemanager_v3
        from google.oauth2 import service_account
    except ImportError:
        return ProviderResult(
            provider="gcp",
            account_info="",
            connection_error="GCP SDK not installed. Run: pip install google-cloud-resource-manager google-cloud-iam",
        )

    try:
        creds_file = credentials.get("credentials_file")
        project_id = credentials.get("project_id")

        if not creds_file or not os.path.exists(creds_file):
            return ProviderResult(
                provider="gcp",
                account_info="",
                connection_error="GCP credentials file not found",
            )

        # Load credentials
        gcp_credentials = service_account.Credentials.from_service_account_file(creds_file)

        # Get service account email
        with open(creds_file) as f:
            sa_info = json.load(f)
            sa_email = sa_info.get("client_email", "unknown")
            if not project_id:
                project_id = sa_info.get("project_id")

        account_info = f"Project: {project_id} | SA: {sa_email}"

        result = ProviderResult(provider="gcp", account_info=account_info)

        # Get IAM policy for the project
        assigned_roles = set()
        try:
            client = resourcemanager_v3.ProjectsClient(credentials=gcp_credentials)
            request = resourcemanager_v3.GetIamPolicyRequest(resource=f"projects/{project_id}")
            policy = client.get_iam_policy(request=request)

            for binding in policy.bindings:
                for member in binding.members:
                    if sa_email in member:
                        assigned_roles.add(binding.role)

        except Exception as e:
            result.connection_error = f"Error getting IAM policy: {e}"
            return result

        # Check each tool
        for tool_key, tool_config in GCP_TOOLS.items():
            tool_result = check_gcp_tool_permissions(tool_key, tool_config, assigned_roles)
            result.tool_results.append(tool_result)

        return result

    except Exception as e:
        return ProviderResult(provider="gcp", account_info="", connection_error=f"Error: {e}")


def check_gcp_tool_permissions(
    tool_key: str, tool_config: dict, assigned_roles: set
) -> PermissionResult:
    """Check permissions for a specific GCP tool."""
    result = PermissionResult(
        tool_name=tool_key, tool_display_name=tool_config["name"], passed=True
    )

    # Check required roles
    for role in tool_config.get("required_roles", []):
        if role not in assigned_roles:
            result.missing_roles.append(role)
            result.passed = False

    # Note about custom role permissions for CloudSploit
    if tool_key == "cloudsploit" and not tool_config.get("required_roles"):
        result.notes.append("CloudSploit requires a custom role with ~40 specific permissions")
        result.notes.append("See remediation output for custom role definition")
        # Check if any viewer-like role is assigned
        if not any("viewer" in r.lower() for r in assigned_roles):
            result.missing_roles.append("Custom role: AquaCSPMSecurityAudit")
            result.passed = False

    return result


# =============================================================================
# Kubernetes Permission Validation
# =============================================================================


def check_kubernetes_permissions(credentials: dict, args) -> ProviderResult:
    """Check Kubernetes RBAC permissions for all tools."""
    try:
        from kubernetes import client, config
        from kubernetes.client.rest import ApiException
    except ImportError:
        return ProviderResult(
            provider="kubernetes",
            account_info="",
            connection_error="kubernetes SDK not installed. Run: pip install kubernetes",
        )

    try:
        kubeconfig = credentials.get("kubeconfig")
        context = credentials.get("context")

        # Load kubeconfig
        config.load_kube_config(config_file=kubeconfig, context=context)

        # Get cluster info
        v1 = client.CoreV1Api()
        version_api = client.VersionApi()
        version_info = version_api.get_code()

        # Get current context
        _, active_context = config.list_kube_config_contexts(config_file=kubeconfig)
        context_name = active_context["name"] if active_context else "default"
        cluster_name = active_context.get("context", {}).get("cluster", "unknown")

        account_info = (
            f"Context: {context_name} | Cluster: {cluster_name} | K8s: {version_info.git_version}"
        )

        result = ProviderResult(provider="kubernetes", account_info=account_info)

        auth_api = client.AuthorizationV1Api()

        # Check each tool
        for tool_key, tool_config in KUBERNETES_TOOLS.items():
            tool_result = check_kubernetes_tool_permissions(auth_api, tool_key, tool_config)
            result.tool_results.append(tool_result)

        return result

    except Exception as e:
        return ProviderResult(
            provider="kubernetes", account_info="", connection_error=f"Error: {e}"
        )


def check_kubernetes_tool_permissions(
    auth_api, tool_key: str, tool_config: dict
) -> PermissionResult:
    """Check RBAC permissions for a specific Kubernetes tool."""
    from kubernetes import client
    from kubernetes.client.rest import ApiException

    result = PermissionResult(
        tool_name=tool_key, tool_display_name=tool_config["name"], passed=True
    )

    # Handle tools that need host access instead of RBAC
    if tool_config.get("host_access_required"):
        result.notes.append(tool_config.get("note", "Requires host-level access"))
        result.notes.append("Run as a Kubernetes Job with hostPID and volume mounts")
        return result

    # Check RBAC permissions using SelfSubjectAccessReview
    required_verbs = tool_config.get("required_verbs", [])
    required_resources = tool_config.get("required_resources", [])

    for resource_spec in required_resources:
        api_groups = resource_spec.get("apiGroups", [""])
        resources = resource_spec.get("resources", [])

        for api_group in api_groups:
            for resource in resources:
                for verb in required_verbs:
                    # Test this specific permission
                    try:
                        review = client.V1SelfSubjectAccessReview(
                            spec=client.V1SelfSubjectAccessReviewSpec(
                                resource_attributes=client.V1ResourceAttributes(
                                    verb=verb,
                                    group=api_group if api_group else "",
                                    resource=resource if resource != "*" else "pods",
                                )
                            )
                        )
                        response = auth_api.create_self_subject_access_review(review)

                        if not response.status.allowed:
                            perm_str = (
                                f"{verb} on {api_group}/{resource}"
                                if api_group
                                else f"{verb} on {resource}"
                            )
                            result.missing_permissions.append(perm_str)
                            result.passed = False
                            break  # One verb failure is enough

                    except ApiException as e:
                        result.errors.append(f"Error checking {verb} {resource}: {e.reason}")

    # Add notes if present
    if tool_config.get("note"):
        result.notes.append(tool_config["note"])

    return result


# =============================================================================
# Output Formatting
# =============================================================================


def print_results(results: list[ProviderResult], args):
    """Print results to console."""
    print()
    print("=" * 80)
    print(f"{Colors.BOLD}Cloud Security Audit Stack - Permission Validator{Colors.NC}")
    print("=" * 80)
    print()

    total_pass = 0
    total_fail = 0
    failed_tools = []

    for provider_result in results:
        provider_name = provider_result.provider.upper()

        if provider_result.connection_error:
            print(f"{Colors.BOLD}{provider_name}{Colors.NC}")
            print("-" * 80)
            print(f"{Colors.RED}[ERROR]{Colors.NC} {provider_result.connection_error}")
            print()
            continue

        print(f"{Colors.BOLD}{provider_name}{Colors.NC} ({provider_result.account_info})")
        print("-" * 80)

        for tool_result in provider_result.tool_results:
            if tool_result.passed:
                status = f"{Colors.GREEN}[PASS]{Colors.NC}"
                total_pass += 1
            else:
                status = f"{Colors.RED}[FAIL]{Colors.NC}"
                total_fail += 1
                failed_tools.append((provider_result.provider, tool_result))

            print(f"{status} {tool_result.tool_display_name:15} - ", end="")

            if tool_result.passed:
                print("All required permissions present")
            else:
                issues = []
                if tool_result.missing_policies:
                    issues.append(f"{len(tool_result.missing_policies)} missing policies")
                if tool_result.missing_roles:
                    issues.append(f"{len(tool_result.missing_roles)} missing roles")
                if tool_result.missing_permissions:
                    issues.append(f"{len(tool_result.missing_permissions)} missing permissions")
                print(", ".join(issues))

                # Show details
                for policy in tool_result.missing_policies:
                    print(f"       {Colors.YELLOW}Missing policy:{Colors.NC} {policy}")
                for role in tool_result.missing_roles:
                    print(f"       {Colors.YELLOW}Missing role:{Colors.NC} {role}")
                for perm in tool_result.missing_permissions[:5]:  # Limit to 5
                    print(f"       {Colors.YELLOW}Missing:{Colors.NC} {perm}")
                if len(tool_result.missing_permissions) > 5:
                    print(f"       ... and {len(tool_result.missing_permissions) - 5} more")

            # Show notes in verbose mode
            if args.verbose and tool_result.notes:
                for note in tool_result.notes:
                    print(f"       {Colors.CYAN}Note:{Colors.NC} {note}")

            # Show errors
            for error in tool_result.errors:
                print(f"       {Colors.RED}Error:{Colors.NC} {error}")

        print()

    # Summary
    print("=" * 80)
    total = total_pass + total_fail
    if total_fail == 0:
        print(f"{Colors.GREEN}SUMMARY: {total_pass}/{total} tools ready{Colors.NC}")
    else:
        print(
            f"{Colors.YELLOW}SUMMARY: {total_pass}/{total} tools ready | {total_fail} tools need attention{Colors.NC}"
        )
    print("=" * 80)

    # Remediation hint
    if failed_tools and not args.remediation:
        print()
        print(f"Run with {Colors.CYAN}--remediation{Colors.NC} for detailed fix instructions")
        print(f"Or export with {Colors.CYAN}--output report.md{Colors.NC}")

    return failed_tools


def print_remediation(failed_tools: list, args):
    """Print detailed remediation instructions."""
    if not failed_tools or not args.remediation:
        return

    print()
    print("=" * 80)
    print(f"{Colors.BOLD}REMEDIATION INSTRUCTIONS{Colors.NC}")
    print("=" * 80)
    print()

    for provider, tool_result in failed_tools:
        print(f"{Colors.BOLD}## {provider.upper()} - {tool_result.tool_display_name}{Colors.NC}")
        print()

        if provider == "aws":
            print_aws_remediation(tool_result)
        elif provider == "azure":
            print_azure_remediation(tool_result)
        elif provider == "gcp":
            print_gcp_remediation(tool_result)
        elif provider == "kubernetes":
            print_kubernetes_remediation(tool_result)

        print()


def print_aws_remediation(tool_result: PermissionResult):
    """Print AWS-specific remediation."""
    for policy in tool_result.missing_policies:
        policy_arn = AWS_MANAGED_POLICIES.get(policy, f"arn:aws:iam::aws:policy/{policy}")

        print(f"### Missing: {policy} Policy")
        print()
        print("**Option 1: AWS CLI (Recommended)**")
        print("```bash")
        print("# For IAM User:")
        print("aws iam attach-user-policy \\")
        print("    --user-name YOUR_USER_NAME \\")
        print(f"    --policy-arn {policy_arn}")
        print()
        print("# For IAM Role:")
        print("aws iam attach-role-policy \\")
        print("    --role-name YOUR_ROLE_NAME \\")
        print(f"    --policy-arn {policy_arn}")
        print("```")
        print()
        print("**Option 2: AWS Console**")
        print("1. Navigate to IAM Console: https://console.aws.amazon.com/iam")
        print("2. Select Users or Roles from the left menu")
        print("3. Click on your user/role name")
        print('4. Click "Add permissions" > "Attach policies directly"')
        print(f'5. Search for "{policy}"')
        print('6. Select the checkbox and click "Add permissions"')
        print()

    # Prowler specific additions policy
    if tool_result.tool_name == "prowler" and tool_result.missing_permissions:
        print("### Prowler Additions Policy")
        print()
        print("Create an inline policy with the following JSON:")
        print("```json")
        print(json.dumps(PROWLER_ADDITIONS_POLICY, indent=2))
        print("```")
        print()


def print_azure_remediation(tool_result: PermissionResult):
    """Print Azure-specific remediation."""
    for role in tool_result.missing_roles:
        print(f"### Missing: {role} Role")
        print()
        print("**Option 1: Azure CLI**")
        print("```bash")
        print("# Get your service principal object ID")
        print("SP_OBJECT_ID=$(az ad sp show --id YOUR_CLIENT_ID --query id -o tsv)")
        print()
        print("# Assign the role at subscription level")
        print("az role assignment create \\")
        print("    --assignee $SP_OBJECT_ID \\")
        print(f'    --role "{role}" \\')
        print("    --scope /subscriptions/YOUR_SUBSCRIPTION_ID")
        print("```")
        print()
        print("**Option 2: Azure Portal**")
        print("1. Navigate to your Subscription in Azure Portal")
        print('2. Click "Access control (IAM)"')
        print('3. Click "Add" > "Add role assignment"')
        print(f'4. Select role: "{role}"')
        print('5. Select "User, group, or service principal"')
        print("6. Search for your service principal name")
        print('7. Click "Review + assign"')
        print()


def print_gcp_remediation(tool_result: PermissionResult):
    """Print GCP-specific remediation."""
    for role in tool_result.missing_roles:
        if "custom" in role.lower():
            # CloudSploit custom role
            print(f"### Missing: {role}")
            print()
            print("Create a custom role with the following YAML:")
            print("```yaml")
            print("# Save as aqua-security-audit-role.yaml")
            print(f"title: {CLOUDSPLOIT_GCP_CUSTOM_ROLE['title']}")
            print(f"description: {CLOUDSPLOIT_GCP_CUSTOM_ROLE['description']}")
            print(f"stage: {CLOUDSPLOIT_GCP_CUSTOM_ROLE['stage']}")
            print("includedPermissions:")
            for perm in CLOUDSPLOIT_GCP_CUSTOM_ROLE["includedPermissions"][:10]:
                print(f"  - {perm}")
            print("  # ... see full list in permission_requirements.py")
            print("```")
            print()
            print("**Create and assign the role:**")
            print("```bash")
            print("# Create the custom role")
            print("gcloud iam roles create AquaCSPMSecurityAudit \\")
            print("    --project=YOUR_PROJECT_ID \\")
            print("    --file=aqua-security-audit-role.yaml")
            print()
            print("# Assign to service account")
            print("gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \\")
            print('    --member="serviceAccount:YOUR_SA_EMAIL" \\')
            print('    --role="projects/YOUR_PROJECT_ID/roles/AquaCSPMSecurityAudit"')
            print("```")
        else:
            print(f"### Missing: {role}")
            print()
            print("**Assign the role using gcloud:**")
            print("```bash")
            print("gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \\")
            print('    --member="serviceAccount:YOUR_SA_EMAIL" \\')
            print(f'    --role="{role}"')
            print("```")
            print()
            print("**Or via GCP Console:**")
            print("1. Navigate to IAM & Admin > IAM")
            print("2. Click the pencil icon next to your service account")
            print('3. Click "Add another role"')
            print(f'4. Search for and select "{GCP_PREDEFINED_ROLES.get(role, role)}"')
            print('5. Click "Save"')
        print()


def print_kubernetes_remediation(tool_result: PermissionResult):
    """Print Kubernetes-specific remediation."""
    print("### Required RBAC Configuration")
    print()

    if tool_result.tool_name == "kubescape":
        print("Apply the following ClusterRole and ClusterRoleBinding:")
        print("```yaml")
        print(KUBESCAPE_CLUSTER_ROLE)
        print("```")
    elif tool_result.tool_name == "trivy":
        print("Apply the following ClusterRole and ClusterRoleBinding:")
        print("```yaml")
        print(TRIVY_CLUSTER_ROLE)
        print("```")
    else:
        print("Create a ClusterRole with the required permissions:")
        print("```yaml")
        print("apiVersion: rbac.authorization.k8s.io/v1")
        print("kind: ClusterRole")
        print("metadata:")
        print(f"  name: {tool_result.tool_name}-scanner")
        print("rules:")
        print('  - apiGroups: ["*"]')
        print('    resources: ["*"]')
        print('    verbs: ["get", "list", "watch"]')
        print("```")

    print()
    print("**Apply with kubectl:**")
    print("```bash")
    print("kubectl apply -f rbac-config.yaml")
    print("```")


def export_results(results: list[ProviderResult], failed_tools: list, args):
    """Export results to file."""
    if not args.output:
        return

    output_path = Path(args.output)
    ext = output_path.suffix.lower()

    if ext == ".json":
        export_json(results, output_path)
    elif ext == ".md":
        export_markdown(results, failed_tools, output_path, args)
    else:
        export_text(results, failed_tools, output_path, args)

    print(f"\nResults exported to: {output_path}")


def export_json(results: list[ProviderResult], output_path: Path):
    """Export results as JSON."""
    data = {"results": []}

    for provider_result in results:
        provider_data = {
            "provider": provider_result.provider,
            "account_info": provider_result.account_info,
            "connection_error": provider_result.connection_error,
            "tools": [],
        }

        for tool_result in provider_result.tool_results:
            provider_data["tools"].append(
                {
                    "name": tool_result.tool_name,
                    "display_name": tool_result.tool_display_name,
                    "passed": tool_result.passed,
                    "missing_policies": tool_result.missing_policies,
                    "missing_roles": tool_result.missing_roles,
                    "missing_permissions": tool_result.missing_permissions,
                    "errors": tool_result.errors,
                    "notes": tool_result.notes,
                }
            )

        data["results"].append(provider_data)

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)


def export_markdown(results: list[ProviderResult], failed_tools: list, output_path: Path, args):
    """Export results as Markdown."""
    lines = [
        "# Cloud Security Audit Stack - Permission Validation Report",
        "",
        "## Summary",
        "",
    ]

    total_pass = 0
    total_fail = 0

    for provider_result in results:
        if provider_result.connection_error:
            continue
        for tool_result in provider_result.tool_results:
            if tool_result.passed:
                total_pass += 1
            else:
                total_fail += 1

    lines.append(f"- **Tools Ready:** {total_pass}")
    lines.append(f"- **Tools Need Attention:** {total_fail}")
    lines.append("")

    # Results by provider
    for provider_result in results:
        lines.append(f"## {provider_result.provider.upper()}")
        lines.append("")

        if provider_result.connection_error:
            lines.append(f"**Error:** {provider_result.connection_error}")
            lines.append("")
            continue

        lines.append(f"**{provider_result.account_info}**")
        lines.append("")
        lines.append("| Tool | Status | Issues |")
        lines.append("|------|--------|--------|")

        for tool_result in provider_result.tool_results:
            status = "PASS" if tool_result.passed else "FAIL"
            issues = []
            if tool_result.missing_policies:
                issues.extend(tool_result.missing_policies)
            if tool_result.missing_roles:
                issues.extend(tool_result.missing_roles)
            if tool_result.missing_permissions:
                issues.append(f"{len(tool_result.missing_permissions)} permissions")

            issues_str = ", ".join(issues) if issues else "-"
            lines.append(f"| {tool_result.tool_display_name} | {status} | {issues_str} |")

        lines.append("")

    # Remediation section
    if failed_tools and args.remediation:
        lines.append("## Remediation Instructions")
        lines.append("")

        for provider, tool_result in failed_tools:
            lines.append(f"### {provider.upper()} - {tool_result.tool_display_name}")
            lines.append("")

            # Add provider-specific remediation
            # (simplified for markdown export)
            if provider == "aws":
                for policy in tool_result.missing_policies:
                    policy_arn = AWS_MANAGED_POLICIES.get(policy)
                    lines.append(f"**Attach {policy} policy:**")
                    lines.append("```bash")
                    lines.append(
                        f"aws iam attach-role-policy --role-name YOUR_ROLE --policy-arn {policy_arn}"
                    )
                    lines.append("```")
                    lines.append("")

            elif provider == "azure":
                for role in tool_result.missing_roles:
                    lines.append(f"**Assign {role} role:**")
                    lines.append("```bash")
                    lines.append(
                        f'az role assignment create --assignee YOUR_SP_ID --role "{role}" --scope /subscriptions/YOUR_SUB_ID'
                    )
                    lines.append("```")
                    lines.append("")

            elif provider == "gcp":
                for role in tool_result.missing_roles:
                    lines.append(f"**Assign {role}:**")
                    lines.append("```bash")
                    lines.append(
                        f'gcloud projects add-iam-policy-binding YOUR_PROJECT --member="serviceAccount:YOUR_SA" --role="{role}"'
                    )
                    lines.append("```")
                    lines.append("")

            elif provider == "kubernetes":
                lines.append("**Apply RBAC configuration:**")
                lines.append("```bash")
                lines.append("kubectl apply -f rbac-config.yaml")
                lines.append("```")
                lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))


def export_text(results: list[ProviderResult], failed_tools: list, output_path: Path, args):
    """Export results as plain text."""
    # Disable colors for file output
    Colors.disable()

    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        print_results(results, args)
        if args.remediation:
            print_remediation(failed_tools, args)

    with open(output_path, "w") as out:
        out.write(f.getvalue())


# =============================================================================
# CLI Interface
# =============================================================================


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate cloud credentials have required permissions for security scanning tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --provider aws
  %(prog)s --provider all --output report.md --remediation
  %(prog)s --provider aws --aws-profile my-profile
  %(prog)s --provider kubernetes --kubeconfig ~/.kube/config
        """,
    )

    # Provider selection
    parser.add_argument(
        "--provider",
        "-p",
        choices=["aws", "azure", "gcp", "kubernetes", "all"],
        default="all",
        help="Provider to check (default: all)",
    )

    # AWS credentials
    aws_group = parser.add_argument_group("AWS Credentials")
    aws_group.add_argument("--aws-profile", help="AWS profile name")
    aws_group.add_argument("--aws-access-key", help="AWS access key ID")
    aws_group.add_argument("--aws-secret-key", help="AWS secret access key")
    aws_group.add_argument("--aws-region", default="us-east-1", help="AWS region")

    # Azure credentials
    azure_group = parser.add_argument_group("Azure Credentials")
    azure_group.add_argument("--azure-tenant-id", help="Azure tenant ID")
    azure_group.add_argument("--azure-client-id", help="Azure client/application ID")
    azure_group.add_argument("--azure-client-secret", help="Azure client secret")
    azure_group.add_argument("--azure-subscription-id", help="Azure subscription ID")
    azure_group.add_argument(
        "--azure-object-id", help="Azure service principal object ID (for role lookups)"
    )

    # GCP credentials
    gcp_group = parser.add_argument_group("GCP Credentials")
    gcp_group.add_argument("--gcp-credentials-file", help="Path to GCP service account JSON")
    gcp_group.add_argument("--gcp-project-id", help="GCP project ID")

    # Kubernetes credentials
    k8s_group = parser.add_argument_group("Kubernetes Credentials")
    k8s_group.add_argument("--kubeconfig", help="Path to kubeconfig file")
    k8s_group.add_argument("--kube-context", help="Kubernetes context to use")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--output", "-o", help="Export results to file (.json, .md, .txt)")
    output_group.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    output_group.add_argument(
        "--remediation",
        "-r",
        action="store_true",
        help="Include remediation instructions",
    )
    output_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be checked without API calls",
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Check if output is to a file (disable colors)
    if args.output:
        Colors.disable()

    results = []

    providers_to_check = []
    if args.provider == "all":
        providers_to_check = ["aws", "azure", "gcp", "kubernetes"]
    else:
        providers_to_check = [args.provider]

    # Check each provider
    for provider in providers_to_check:
        if provider == "aws":
            creds = load_aws_credentials(args)
            if creds:
                if args.dry_run:
                    print("[DRY-RUN] Would check AWS permissions (credentials found)")
                else:
                    results.append(check_aws_permissions(creds, args))
            else:
                results.append(
                    ProviderResult(
                        provider="aws",
                        account_info="",
                        connection_error="No AWS credentials found. Use --aws-profile or --aws-access-key/--aws-secret-key, or place credentials in credentials/aws/",
                    )
                )

        elif provider == "azure":
            creds = load_azure_credentials(args)
            if creds:
                if args.dry_run:
                    print("[DRY-RUN] Would check Azure permissions (credentials found)")
                else:
                    results.append(check_azure_permissions(creds, args))
            else:
                results.append(
                    ProviderResult(
                        provider="azure",
                        account_info="",
                        connection_error="No Azure credentials found. Use --azure-* options or place credentials in credentials/azure/credentials.json",
                    )
                )

        elif provider == "gcp":
            creds = load_gcp_credentials(args)
            if creds:
                if args.dry_run:
                    print("[DRY-RUN] Would check GCP permissions (credentials found)")
                else:
                    results.append(check_gcp_permissions(creds, args))
            else:
                results.append(
                    ProviderResult(
                        provider="gcp",
                        account_info="",
                        connection_error="No GCP credentials found. Use --gcp-credentials-file or place credentials in credentials/gcp/credentials.json",
                    )
                )

        elif provider == "kubernetes":
            creds = load_kubernetes_credentials(args)
            if creds:
                if args.dry_run:
                    print("[DRY-RUN] Would check Kubernetes permissions (credentials found)")
                else:
                    results.append(check_kubernetes_permissions(creds, args))
            else:
                results.append(
                    ProviderResult(
                        provider="kubernetes",
                        account_info="",
                        connection_error="No kubeconfig found. Use --kubeconfig or place config in kubeconfigs/config",
                    )
                )

    if args.dry_run:
        return 0

    # Print results
    failed_tools = print_results(results, args)

    # Print remediation
    if args.remediation:
        print_remediation(failed_tools, args)

    # Export if requested
    export_results(results, failed_tools, args)

    # Return exit code
    return 1 if failed_tools else 0


if __name__ == "__main__":
    sys.exit(main())
