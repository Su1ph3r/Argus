"""
Permission requirements for each security scanning tool.

This module defines the required permissions, policies, and roles needed
for each tool in Nubicustos.
"""

# =============================================================================
# AWS Tool Requirements
# =============================================================================

AWS_MANAGED_POLICIES = {
    "SecurityAudit": "arn:aws:iam::aws:policy/SecurityAudit",
    "ReadOnlyAccess": "arn:aws:iam::aws:policy/ReadOnlyAccess",
    "ViewOnlyAccess": "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
}

AWS_TOOLS = {
    "prowler": {
        "name": "Prowler",
        "description": "AWS Security Posture Management",
        "required_managed_policies": ["SecurityAudit"],
        "required_actions": [
            # Prowler additions policy - key permissions to test
            "account:GetAlternateContact",
            "appstream:DescribeFleets",
            "backup:ListBackupPlans",
            "cloudtrail:GetInsightSelectors",
            "cognito-idp:GetUserPoolMfaConfig",
            "ds:DescribeDirectories",
            "dynamodb:GetResourcePolicy",
            "ec2:GetEbsEncryptionByDefault",
            "ec2:GetSnapshotBlockPublicAccessState",
            "ecr:GetRegistryScanningConfiguration",
            "elasticfilesystem:DescribeBackupPolicy",
            "glue:GetSecurityConfigurations",
            "lambda:GetFunctionUrlConfig",
            "logs:FilterLogEvents",
            "macie2:GetMacieSession",
            "s3:GetAccountPublicAccessBlock",
            "shield:GetSubscriptionState",
            "ssm:GetDocument",
            "support:DescribeTrustedAdvisorChecks",
            "wellarchitected:ListWorkloads",
        ],
        "remediation_policy_name": "ProwlerAdditionsPolicy",
    },
    "scoutsuite": {
        "name": "ScoutSuite",
        "description": "Multi-cloud security auditing",
        "required_managed_policies": ["ReadOnlyAccess", "SecurityAudit"],
        "required_actions": [
            # Key ScoutSuite permissions
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketAcl",
            "s3:GetBucketPolicy",
            "ec2:DescribeInstances",
            "ec2:DescribeSecurityGroups",
            "iam:ListUsers",
            "iam:ListRoles",
            "iam:GetAccountPasswordPolicy",
            "cloudtrail:DescribeTrails",
            "rds:DescribeDBInstances",
        ],
        "remediation_policy_name": None,  # Uses managed policies only
    },
    "cloudsploit": {
        "name": "CloudSploit",
        "description": "Cloud Security Posture Management",
        "required_managed_policies": ["SecurityAudit"],
        "required_actions": [
            "ec2:DescribeInstances",
            "ec2:DescribeSecurityGroups",
            "s3:ListAllMyBuckets",
            "iam:ListUsers",
            "cloudtrail:DescribeTrails",
        ],
        "remediation_policy_name": None,
    },
    "cloud_custodian": {
        "name": "Cloud Custodian",
        "description": "Cloud governance rules engine",
        "required_managed_policies": ["ReadOnlyAccess"],
        "required_actions": [
            "ec2:DescribeInstances",
            "s3:ListAllMyBuckets",
            "iam:ListUsers",
            "tag:GetResources",
        ],
        "remediation_policy_name": None,
    },
    "cartography": {
        "name": "Cartography",
        "description": "Infrastructure asset mapping",
        "required_managed_policies": ["SecurityAudit"],
        "required_actions": [
            "ec2:DescribeInstances",
            "ec2:DescribeSecurityGroups",
            "iam:ListUsers",
            "iam:ListRoles",
            "s3:ListAllMyBuckets",
        ],
        "remediation_policy_name": None,
    },
}

# Prowler additions policy JSON for remediation
PROWLER_ADDITIONS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ProwlerAdditions",
            "Effect": "Allow",
            "Action": [
                "account:Get*",
                "appstream:Describe*",
                "appstream:List*",
                "backup:List*",
                "cloudtrail:GetInsightSelectors",
                "codeartifact:List*",
                "codebuild:BatchGet*",
                "cognito-idp:GetUserPoolMfaConfig",
                "dlm:Get*",
                "drs:Describe*",
                "ds:Get*",
                "ds:Describe*",
                "ds:List*",
                "dynamodb:GetResourcePolicy",
                "ec2:GetEbsEncryptionByDefault",
                "ec2:GetSnapshotBlockPublicAccessState",
                "ec2:GetInstanceMetadataDefaults",
                "ecr:Describe*",
                "ecr:GetRegistryScanningConfiguration",
                "elasticfilesystem:DescribeBackupPolicy",
                "glue:GetConnections",
                "glue:GetSecurityConfiguration*",
                "glue:SearchTables",
                "lambda:GetFunction*",
                "logs:FilterLogEvents",
                "lightsail:GetRelationalDatabases",
                "macie2:GetMacieSession",
                "macie2:GetAutomatedDiscoveryConfiguration",
                "s3:GetAccountPublicAccessBlock",
                "shield:DescribeProtection",
                "shield:GetSubscriptionState",
                "securityhub:BatchImportFindings",
                "securityhub:GetFindings",
                "ssm:GetDocument",
                "ssm-incidents:List*",
                "states:ListTagsForResource",
                "support:Describe*",
                "tag:GetTagKeys",
                "wellarchitected:List*",
            ],
            "Resource": "*",
        },
        {
            "Sid": "ProwlerAPIGateway",
            "Effect": "Allow",
            "Action": ["apigateway:GET"],
            "Resource": [
                "arn:aws:apigateway:*::/restapis/*",
                "arn:aws:apigateway:*::/apis/*",
            ],
        },
    ],
}

# =============================================================================
# Azure Tool Requirements
# =============================================================================

AZURE_BUILTIN_ROLES = {
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "Security Reader": "39bc4728-0917-49c7-9d2c-d95423bc2eb4",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
}

AZURE_GRAPH_PERMISSIONS = {
    "Directory.Read.All": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
    "Group.Read.All": "5b567255-7703-4780-807c-7be8301ae99b",
    "Application.Read.All": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
}

AZURE_TOOLS = {
    "scoutsuite": {
        "name": "ScoutSuite",
        "description": "Multi-cloud security auditing",
        "required_roles": ["Reader", "Security Reader"],
        "required_graph_permissions": ["Directory.Read.All"],
        "scope": "subscription",
    },
    "cloudsploit": {
        "name": "CloudSploit",
        "description": "Cloud Security Posture Management",
        "required_roles": ["Security Reader"],
        "required_graph_permissions": [],
        "scope": "subscription",
    },
    "cloud_custodian": {
        "name": "Cloud Custodian",
        "description": "Cloud governance rules engine",
        "required_roles": ["Reader"],
        "required_graph_permissions": [],
        "scope": "subscription",
    },
}

# =============================================================================
# GCP Tool Requirements
# =============================================================================

GCP_PREDEFINED_ROLES = {
    "roles/viewer": "Viewer",
    "roles/iam.securityReviewer": "Security Reviewer",
    "roles/stackdriver.accounts.viewer": "Stackdriver Accounts Viewer",
    "roles/cloudasset.viewer": "Cloud Asset Viewer",
}

GCP_TOOLS = {
    "prowler": {
        "name": "Prowler",
        "description": "GCP Security Posture Management",
        "required_roles": ["roles/viewer"],
        "required_permissions": [
            "compute.instances.list",
            "storage.buckets.list",
            "iam.serviceAccounts.list",
        ],
    },
    "scoutsuite": {
        "name": "ScoutSuite",
        "description": "Multi-cloud security auditing",
        "required_roles": [
            "roles/viewer",
            "roles/iam.securityReviewer",
            "roles/stackdriver.accounts.viewer",
        ],
        "required_permissions": [
            "compute.instances.list",
            "storage.buckets.list",
            "iam.serviceAccounts.list",
            "logging.sinks.list",
            "monitoring.alertPolicies.list",
        ],
    },
    "cloudsploit": {
        "name": "CloudSploit",
        "description": "Cloud Security Posture Management",
        "required_roles": [],  # Uses custom role
        "required_permissions": [
            "cloudasset.assets.listResource",
            "cloudkms.cryptoKeys.list",
            "cloudkms.keyRings.list",
            "cloudsql.instances.list",
            "cloudsql.users.list",
            "compute.autoscalers.list",
            "compute.backendServices.list",
            "compute.disks.list",
            "compute.firewalls.list",
            "compute.healthChecks.list",
            "compute.instanceGroups.list",
            "compute.instances.getIamPolicy",
            "compute.instances.list",
            "compute.networks.list",
            "compute.projects.get",
            "compute.securityPolicies.list",
            "compute.subnetworks.list",
            "compute.targetHttpProxies.list",
            "container.clusters.list",
            "dns.managedZones.list",
            "iam.serviceAccountKeys.list",
            "iam.serviceAccounts.list",
            "logging.logMetrics.list",
            "logging.sinks.list",
            "monitoring.alertPolicies.list",
            "resourcemanager.folders.get",
            "resourcemanager.folders.getIamPolicy",
            "resourcemanager.folders.list",
            "resourcemanager.projects.get",
            "resourcemanager.projects.getIamPolicy",
        ],
        "custom_role_name": "AquaCSPMSecurityAudit",
    },
}

# CloudSploit custom role definition for GCP
CLOUDSPLOIT_GCP_CUSTOM_ROLE = {
    "title": "Aqua CSPM Security Audit",
    "description": "Custom role for CloudSploit security scanning",
    "stage": "GA",
    "includedPermissions": GCP_TOOLS["cloudsploit"]["required_permissions"],
}

# =============================================================================
# Kubernetes Tool Requirements
# =============================================================================

KUBERNETES_TOOLS = {
    "kubescape": {
        "name": "Kubescape",
        "description": "Kubernetes security platform",
        "required_verbs": ["get", "list", "watch"],
        "required_resources": [
            {"apiGroups": [""], "resources": ["*"]},
            {"apiGroups": ["apps"], "resources": ["*"]},
            {"apiGroups": ["batch"], "resources": ["*"]},
            {"apiGroups": ["networking.k8s.io"], "resources": ["*"]},
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["*"]},
            {"apiGroups": ["policy"], "resources": ["*"]},
        ],
        "cluster_wide": True,
    },
    "trivy": {
        "name": "Trivy",
        "description": "Container and Kubernetes security scanner",
        "required_verbs": ["list"],
        "required_resources": [
            {"apiGroups": [""], "resources": ["*"]},
            {"apiGroups": ["apps"], "resources": ["*"]},
            {"apiGroups": ["batch"], "resources": ["*"]},
            {"apiGroups": ["networking.k8s.io"], "resources": ["*"]},
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["*"]},
        ],
        "cluster_wide": True,
        "node_collector_permissions": {
            "required_verbs": ["get", "list", "create", "delete", "watch"],
            "required_resources": [
                {"apiGroups": [""], "resources": ["nodes/proxy", "pods/log"]},
                {"apiGroups": [""], "resources": ["events"]},
                {"apiGroups": ["batch"], "resources": ["jobs", "cronjobs"]},
                {"apiGroups": [""], "resources": ["namespaces"]},
            ],
        },
    },
    "polaris": {
        "name": "Polaris",
        "description": "Kubernetes best practices validation",
        "required_verbs": ["get", "list"],
        "required_resources": [
            {"apiGroups": [""], "resources": ["pods", "namespaces"]},
            {
                "apiGroups": ["apps"],
                "resources": ["deployments", "daemonsets", "statefulsets", "replicasets"],
            },
            {"apiGroups": ["batch"], "resources": ["jobs", "cronjobs"]},
        ],
        "cluster_wide": True,
    },
    "kube_bench": {
        "name": "kube-bench",
        "description": "CIS Kubernetes Benchmark",
        "required_verbs": [],  # Host-level access, not RBAC
        "required_resources": [],
        "cluster_wide": False,
        "host_access_required": True,
        "note": "Requires hostPID and host volume mounts, not standard RBAC",
    },
    "kube_hunter": {
        "name": "kube-hunter",
        "description": "Kubernetes penetration testing",
        "required_verbs": ["get", "list"],
        "required_resources": [
            {"apiGroups": [""], "resources": ["pods", "services", "secrets", "configmaps"]},
            {"apiGroups": ["apps"], "resources": ["deployments"]},
        ],
        "cluster_wide": True,
        "note": "Tests what permissions the current service account has",
    },
}

# Kubescape ClusterRole YAML for remediation
KUBESCAPE_CLUSTER_ROLE = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubescape-scanner
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubescape-scanner-binding
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: kubescape-scanner
  apiGroup: rbac.authorization.k8s.io
"""

TRIVY_CLUSTER_ROLE = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trivy-scanner
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["list"]
  - apiGroups: ["apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io"]
    resources: ["*"]
    verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: trivy-scanner-binding
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: trivy-scanner
  apiGroup: rbac.authorization.k8s.io
"""

# =============================================================================
# Helper Functions
# =============================================================================


def get_all_aws_tools():
    """Return list of all AWS tool names."""
    return list(AWS_TOOLS.keys())


def get_all_azure_tools():
    """Return list of all Azure tool names."""
    return list(AZURE_TOOLS.keys())


def get_all_gcp_tools():
    """Return list of all GCP tool names."""
    return list(GCP_TOOLS.keys())


def get_all_kubernetes_tools():
    """Return list of all Kubernetes tool names."""
    return list(KUBERNETES_TOOLS.keys())


def get_tool_requirements(provider: str, tool: str) -> dict:
    """Get requirements for a specific tool."""
    providers = {
        "aws": AWS_TOOLS,
        "azure": AZURE_TOOLS,
        "gcp": GCP_TOOLS,
        "kubernetes": KUBERNETES_TOOLS,
    }

    if provider not in providers:
        raise ValueError(f"Unknown provider: {provider}")

    tools = providers[provider]
    if tool not in tools:
        raise ValueError(f"Unknown tool: {tool} for provider {provider}")

    return tools[tool]
