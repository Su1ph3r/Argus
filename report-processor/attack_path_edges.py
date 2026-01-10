#!/usr/bin/env python3
"""
Attack Path Edge Definitions

Maps security findings to graph edges for attack path analysis.
Each edge type defines:
- How to identify the finding (check_id patterns, resource types)
- What kind of attack step it enables
- Entry/exit node types
- MITRE ATT&CK mapping
- Exploitability and impact ratings
"""

import re
from typing import Dict, List, Optional, Tuple, Any


# Entry point types - where attacks can begin
ENTRY_POINT_TYPES = {
    'public_s3': 'Internet-accessible S3 bucket',
    'public_lambda': 'Internet-accessible Lambda function',
    'public_api_gateway': 'Public API Gateway endpoint',
    'public_ec2': 'Internet-facing EC2 instance',
    'public_rds': 'Publicly accessible RDS instance',
    'public_security_group': 'Security group allowing internet access',
    'exposed_credentials': 'Credentials exposed in code/logs/env',
    'weak_iam_policy': 'Overly permissive IAM policy',
}

# Target types - what attackers are trying to reach
TARGET_TYPES = {
    'account_takeover': 'Full AWS account compromise',
    'data_exfiltration': 'Access to sensitive data',
    'persistence': 'Establish persistent access',
    'privilege_escalation': 'Escalate to higher privileges',
    'lateral_movement': 'Move to other resources/accounts',
    'cryptomining': 'Use compute resources for mining',
    'ransomware': 'Encrypt/destroy data for ransom',
}

# Edge definitions - maps findings to attack graph edges
EDGE_DEFINITIONS = {
    # ==========================================================================
    # S3 Entry Points
    # ==========================================================================
    's3_public_access': {
        'name': 'Public S3 Bucket Access',
        'description': 'S3 bucket allows public read/write access',
        'check_patterns': [
            r's3.*public',
            r'bucket.*public.*access',
            r's3.*acl.*public',
            r'publicaccessblocknotconfigured',
        ],
        'resource_types': ['s3', 'awss3bucket', 'bucket'],
        'entry_point_type': 'public_s3',
        'target_types': ['data_exfiltration'],
        'mitre_tactics': ['TA0001', 'TA0009'],  # Initial Access, Collection
        'mitre_techniques': ['T1530'],  # Data from Cloud Storage
        'exploitability': 'confirmed',
        'impact': 'high',
        'requires_auth': False,
        'poc_template': 'aws s3 ls s3://{bucket_name} --no-sign-request',
    },

    's3_no_encryption': {
        'name': 'Unencrypted S3 Bucket',
        'description': 'S3 bucket data is not encrypted at rest',
        'check_patterns': [
            r's3.*encrypt',
            r'bucket.*encryption.*disabled',
            r's3.*sse',
        ],
        'resource_types': ['s3', 'awss3bucket', 'bucket'],
        'entry_point_type': None,
        'target_types': ['data_exfiltration'],
        'mitre_tactics': ['TA0009'],  # Collection
        'mitre_techniques': ['T1530'],
        'exploitability': 'theoretical',
        'impact': 'medium',
        'requires_auth': True,
        'poc_template': 'aws s3api get-bucket-encryption --bucket {bucket_name}',
    },

    # ==========================================================================
    # Lambda Entry Points
    # ==========================================================================
    'lambda_public_access': {
        'name': 'Public Lambda Function',
        'description': 'Lambda function is publicly invokable',
        'check_patterns': [
            r'lambda.*public',
            r'lambda.*policy.*public',
            r'function.*public.*access',
        ],
        'resource_types': ['lambda', 'awslambdafunction', 'function'],
        'entry_point_type': 'public_lambda',
        'target_types': ['privilege_escalation', 'lateral_movement'],
        'mitre_tactics': ['TA0001', 'TA0002'],  # Initial Access, Execution
        'mitre_techniques': ['T1648'],  # Serverless Execution
        'exploitability': 'confirmed',
        'impact': 'high',
        'requires_auth': False,
        'poc_template': 'aws lambda get-policy --function-name {function_name}',
    },

    'lambda_secrets_in_env': {
        'name': 'Secrets in Lambda Environment',
        'description': 'Lambda function has secrets/credentials in environment variables',
        'check_patterns': [
            r'lambda.*secret',
            r'lambda.*credential',
            r'lambda.*env.*password',
            r'lambda.*env.*key',
        ],
        'resource_types': ['lambda', 'awslambdafunction', 'function'],
        'entry_point_type': 'exposed_credentials',
        'target_types': ['privilege_escalation', 'lateral_movement', 'account_takeover'],
        'mitre_tactics': ['TA0006'],  # Credential Access
        'mitre_techniques': ['T1552.005'],  # Cloud Instance Metadata API
        'exploitability': 'confirmed',
        'impact': 'critical',
        'requires_auth': True,
        'poc_template': 'aws lambda get-function-configuration --function-name {function_name} --query "Environment.Variables"',
    },

    # ==========================================================================
    # EC2 Entry Points
    # ==========================================================================
    'ec2_imdsv1_enabled': {
        'name': 'IMDSv1 Enabled on EC2',
        'description': 'EC2 instance allows IMDSv1, enabling SSRF credential theft',
        'check_patterns': [
            r'imds.*v1',
            r'metadata.*v1',
            r'ec2.*imds',
            r'instance.*metadata.*v1',
        ],
        'resource_types': ['ec2', 'awsec2instance', 'instance'],
        'entry_point_type': None,
        'target_types': ['privilege_escalation', 'account_takeover'],
        'mitre_tactics': ['TA0006'],  # Credential Access
        'mitre_techniques': ['T1552.005'],  # Cloud Instance Metadata API
        'exploitability': 'theoretical',
        'impact': 'critical',
        'requires_auth': False,
        'poc_template': 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    },

    'ec2_public_ip': {
        'name': 'EC2 with Public IP',
        'description': 'EC2 instance has a public IP address',
        'check_patterns': [
            r'ec2.*public.*ip',
            r'instance.*public',
        ],
        'resource_types': ['ec2', 'awsec2instance', 'instance'],
        'entry_point_type': 'public_ec2',
        'target_types': ['lateral_movement'],
        'mitre_tactics': ['TA0001'],  # Initial Access
        'mitre_techniques': ['T1190'],  # Exploit Public-Facing Application
        'exploitability': 'theoretical',
        'impact': 'medium',
        'requires_auth': False,
        'poc_template': 'aws ec2 describe-instances --instance-ids {instance_id} --query "Reservations[].Instances[].PublicIpAddress"',
    },

    # ==========================================================================
    # Security Group Issues
    # ==========================================================================
    'sg_open_to_world': {
        'name': 'Security Group Open to Internet',
        'description': 'Security group allows inbound traffic from 0.0.0.0/0',
        'check_patterns': [
            r'security.*group.*0\.0\.0\.0',
            r'sg.*open.*world',
            r'security.*group.*open',
            r'inbound.*unrestricted',
        ],
        'resource_types': ['security-group', 'awsec2securitygroup', 'securitygroup'],
        'entry_point_type': 'public_security_group',
        'target_types': ['lateral_movement'],
        'mitre_tactics': ['TA0001'],  # Initial Access
        'mitre_techniques': ['T1190'],
        'exploitability': 'confirmed',
        'impact': 'high',
        'requires_auth': False,
        'poc_template': 'aws ec2 describe-security-groups --group-ids {sg_id} --query "SecurityGroups[].IpPermissions"',
    },

    'sg_ssh_open': {
        'name': 'SSH Open to Internet',
        'description': 'Security group allows SSH (port 22) from anywhere',
        'check_patterns': [
            r'ssh.*open',
            r'port.*22.*open',
            r'ssh.*0\.0\.0\.0',
        ],
        'resource_types': ['security-group', 'awsec2securitygroup', 'securitygroup'],
        'entry_point_type': 'public_security_group',
        'target_types': ['lateral_movement', 'persistence'],
        'mitre_tactics': ['TA0001', 'TA0008'],  # Initial Access, Lateral Movement
        'mitre_techniques': ['T1021.004'],  # Remote Services: SSH
        'exploitability': 'confirmed',
        'impact': 'high',
        'requires_auth': True,
        'poc_template': 'nmap -p 22 {public_ip}',
    },

    'sg_rdp_open': {
        'name': 'RDP Open to Internet',
        'description': 'Security group allows RDP (port 3389) from anywhere',
        'check_patterns': [
            r'rdp.*open',
            r'port.*3389.*open',
            r'rdp.*0\.0\.0\.0',
        ],
        'resource_types': ['security-group', 'awsec2securitygroup', 'securitygroup'],
        'entry_point_type': 'public_security_group',
        'target_types': ['lateral_movement', 'persistence'],
        'mitre_tactics': ['TA0001', 'TA0008'],
        'mitre_techniques': ['T1021.001'],  # Remote Desktop Protocol
        'exploitability': 'confirmed',
        'impact': 'high',
        'requires_auth': True,
        'poc_template': 'nmap -p 3389 {public_ip}',
    },

    'sg_default_rules': {
        'name': 'Default Security Group In Use',
        'description': 'Resources using default security group with permissive rules',
        'check_patterns': [
            r'default.*security.*group',
            r'security.*group.*default',
        ],
        'resource_types': ['security-group', 'awsec2securitygroup', 'securitygroup', 'vpc'],
        'entry_point_type': 'weak_iam_policy',
        'target_types': ['lateral_movement'],
        'mitre_tactics': ['TA0008'],  # Lateral Movement
        'mitre_techniques': ['T1021'],
        'exploitability': 'theoretical',
        'impact': 'medium',
        'requires_auth': True,
        'poc_template': 'aws ec2 describe-security-groups --filters "Name=group-name,Values=default"',
    },

    # ==========================================================================
    # IAM Privilege Escalation
    # ==========================================================================
    'iam_admin_policy': {
        'name': 'IAM User/Role with Admin Access',
        'description': 'IAM entity has AdministratorAccess or equivalent',
        'check_patterns': [
            r'admin.*access',
            r'iam.*admin',
            r'full.*access',
            r'iam.*\*:\*',
        ],
        'resource_types': ['iam', 'awsiamuser', 'awsiamrole', 'awsiampolicy'],
        'entry_point_type': 'weak_iam_policy',
        'target_types': ['account_takeover', 'privilege_escalation'],
        'mitre_tactics': ['TA0004'],  # Privilege Escalation
        'mitre_techniques': ['T1078.004'],  # Valid Accounts: Cloud
        'exploitability': 'theoretical',
        'impact': 'critical',
        'requires_auth': True,
        'poc_template': 'aws iam list-attached-user-policies --user-name {user_name}',
    },

    'iam_pass_role': {
        'name': 'IAM PassRole Permission',
        'description': 'IAM entity can pass roles to services (privilege escalation vector)',
        'check_patterns': [
            r'pass.*role',
            r'iam:passrole',
        ],
        'resource_types': ['iam', 'awsiamuser', 'awsiamrole', 'awsiampolicy'],
        'entry_point_type': None,
        'target_types': ['privilege_escalation', 'account_takeover'],
        'mitre_tactics': ['TA0004'],  # Privilege Escalation
        'mitre_techniques': ['T1548'],  # Abuse Elevation Control
        'exploitability': 'theoretical',
        'impact': 'critical',
        'requires_auth': True,
        'poc_template': 'aws iam simulate-principal-policy --policy-source-arn {role_arn} --action-names iam:PassRole',
    },

    'iam_create_access_key': {
        'name': 'IAM CreateAccessKey Permission',
        'description': 'IAM entity can create access keys for other users',
        'check_patterns': [
            r'create.*access.*key',
            r'iam:createaccesskey',
        ],
        'resource_types': ['iam', 'awsiamuser', 'awsiamrole', 'awsiampolicy'],
        'entry_point_type': None,
        'target_types': ['persistence', 'account_takeover'],
        'mitre_tactics': ['TA0003', 'TA0004'],  # Persistence, Privilege Escalation
        'mitre_techniques': ['T1098.001'],  # Account Manipulation: Additional Cloud Credentials
        'exploitability': 'theoretical',
        'impact': 'critical',
        'requires_auth': True,
        'poc_template': 'aws iam list-user-policies --user-name {user_name}',
    },

    'iam_no_mfa': {
        'name': 'IAM User Without MFA',
        'description': 'IAM user does not have MFA enabled',
        'check_patterns': [
            r'mfa.*not.*enabled',
            r'no.*mfa',
            r'mfa.*disabled',
        ],
        'resource_types': ['iam', 'awsiamuser'],
        'entry_point_type': 'weak_iam_policy',
        'target_types': ['account_takeover'],
        'mitre_tactics': ['TA0001', 'TA0006'],  # Initial Access, Credential Access
        'mitre_techniques': ['T1078.004'],
        'exploitability': 'theoretical',
        'impact': 'high',
        'requires_auth': False,
        'poc_template': 'aws iam list-mfa-devices --user-name {user_name}',
    },

    'iam_root_account_used': {
        'name': 'Root Account Usage',
        'description': 'AWS root account is being used or has access keys',
        'check_patterns': [
            r'root.*account',
            r'root.*access.*key',
            r'root.*user',
        ],
        'resource_types': ['iam', 'awsaccount'],
        'entry_point_type': 'exposed_credentials',
        'target_types': ['account_takeover'],
        'mitre_tactics': ['TA0001'],  # Initial Access
        'mitre_techniques': ['T1078.004'],
        'exploitability': 'theoretical',
        'impact': 'critical',
        'requires_auth': True,
        'poc_template': 'aws iam get-account-summary --query "SummaryMap.AccountAccessKeysPresent"',
    },

    'iam_old_access_keys': {
        'name': 'Old Access Keys',
        'description': 'IAM access keys have not been rotated in 90+ days',
        'check_patterns': [
            r'access.*key.*rotation',
            r'old.*access.*key',
            r'access.*key.*age',
        ],
        'resource_types': ['iam', 'awsiamuser'],
        'entry_point_type': 'exposed_credentials',
        'target_types': ['persistence'],
        'mitre_tactics': ['TA0003'],  # Persistence
        'mitre_techniques': ['T1098.001'],
        'exploitability': 'theoretical',
        'impact': 'medium',
        'requires_auth': True,
        'poc_template': 'aws iam list-access-keys --user-name {user_name}',
    },

    # ==========================================================================
    # CloudTrail / Logging
    # ==========================================================================
    'cloudtrail_disabled': {
        'name': 'CloudTrail Not Enabled',
        'description': 'CloudTrail logging is not enabled, reducing detection capability',
        'check_patterns': [
            r'cloudtrail.*not.*enabled',
            r'cloudtrail.*disabled',
            r'no.*cloudtrail',
            r'cloudtrail.*not.*configured',
        ],
        'resource_types': ['cloudtrail', 'awscloudtrailtrail'],
        'entry_point_type': None,
        'target_types': ['persistence'],  # Enables persistence by reducing detection
        'mitre_tactics': ['TA0005'],  # Defense Evasion
        'mitre_techniques': ['T1562.008'],  # Disable Cloud Logs
        'exploitability': 'confirmed',
        'impact': 'high',
        'requires_auth': True,
        'poc_template': 'aws cloudtrail describe-trails --query "trailList[].Name"',
    },

    'cloudtrail_no_log_validation': {
        'name': 'CloudTrail Log Validation Disabled',
        'description': 'CloudTrail log file validation is disabled, allowing log tampering',
        'check_patterns': [
            r'log.*validation',
            r'cloudtrail.*validation',
            r'file.*validation.*disabled',
        ],
        'resource_types': ['cloudtrail', 'awscloudtrailtrail'],
        'entry_point_type': None,
        'target_types': ['persistence'],
        'mitre_tactics': ['TA0005'],  # Defense Evasion
        'mitre_techniques': ['T1565'],  # Data Manipulation
        'exploitability': 'theoretical',
        'impact': 'medium',
        'requires_auth': True,
        'poc_template': 'aws cloudtrail describe-trails --query "trailList[].LogFileValidationEnabled"',
    },

    # ==========================================================================
    # RDS Database
    # ==========================================================================
    'rds_public_access': {
        'name': 'RDS Publicly Accessible',
        'description': 'RDS database instance is publicly accessible from internet',
        'check_patterns': [
            r'rds.*public',
            r'database.*public',
            r'rds.*publicly.*accessible',
        ],
        'resource_types': ['rds', 'awsrdsdbinstance', 'database'],
        'entry_point_type': 'public_rds',
        'target_types': ['data_exfiltration'],
        'mitre_tactics': ['TA0001', 'TA0009'],  # Initial Access, Collection
        'mitre_techniques': ['T1190'],
        'exploitability': 'confirmed',
        'impact': 'critical',
        'requires_auth': True,
        'poc_template': 'aws rds describe-db-instances --db-instance-identifier {db_id} --query "DBInstances[].PubliclyAccessible"',
    },

    'rds_no_encryption': {
        'name': 'RDS Not Encrypted',
        'description': 'RDS database is not encrypted at rest',
        'check_patterns': [
            r'rds.*encrypt',
            r'rds.*storage.*encrypt',
            r'database.*encrypt',
        ],
        'resource_types': ['rds', 'awsrdsdbinstance', 'database'],
        'entry_point_type': None,
        'target_types': ['data_exfiltration'],
        'mitre_tactics': ['TA0009'],  # Collection
        'mitre_techniques': ['T1530'],
        'exploitability': 'theoretical',
        'impact': 'high',
        'requires_auth': True,
        'poc_template': 'aws rds describe-db-instances --db-instance-identifier {db_id} --query "DBInstances[].StorageEncrypted"',
    },

    # ==========================================================================
    # KMS
    # ==========================================================================
    'kms_key_rotation_disabled': {
        'name': 'KMS Key Rotation Disabled',
        'description': 'KMS key rotation is not enabled',
        'check_patterns': [
            r'kms.*rotation',
            r'key.*rotation.*disabled',
        ],
        'resource_types': ['kms', 'awskmskey'],
        'entry_point_type': None,
        'target_types': ['persistence'],
        'mitre_tactics': ['TA0003'],  # Persistence
        'mitre_techniques': ['T1098'],  # Account Manipulation
        'exploitability': 'theoretical',
        'impact': 'medium',
        'requires_auth': True,
        'poc_template': 'aws kms get-key-rotation-status --key-id {key_id}',
    },

    # ==========================================================================
    # EBS
    # ==========================================================================
    'ebs_not_encrypted': {
        'name': 'EBS Volume Not Encrypted',
        'description': 'EBS volume is not encrypted at rest',
        'check_patterns': [
            r'ebs.*encrypt',
            r'volume.*encrypt',
            r'ebs.*not.*encrypted',
        ],
        'resource_types': ['ebs', 'awsebsvolume', 'volume'],
        'entry_point_type': None,
        'target_types': ['data_exfiltration'],
        'mitre_tactics': ['TA0009'],  # Collection
        'mitre_techniques': ['T1530'],
        'exploitability': 'theoretical',
        'impact': 'medium',
        'requires_auth': True,
        'poc_template': 'aws ec2 describe-volumes --volume-ids {volume_id} --query "Volumes[].Encrypted"',
    },

    'ebs_snapshot_public': {
        'name': 'EBS Snapshot Publicly Shared',
        'description': 'EBS snapshot is shared publicly',
        'check_patterns': [
            r'snapshot.*public',
            r'ebs.*snapshot.*public',
        ],
        'resource_types': ['ebs', 'snapshot'],
        'entry_point_type': 'public_s3',  # Similar attack vector
        'target_types': ['data_exfiltration'],
        'mitre_tactics': ['TA0009'],  # Collection
        'mitre_techniques': ['T1530'],
        'exploitability': 'confirmed',
        'impact': 'critical',
        'requires_auth': False,
        'poc_template': 'aws ec2 describe-snapshot-attribute --snapshot-id {snapshot_id} --attribute createVolumePermission',
    },
}


def find_matching_edges(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Find edge definitions that match a given finding.

    Args:
        finding: Dictionary containing finding data (check_id, title, resource_type, etc.)

    Returns:
        List of matching edge definitions with populated resource info
    """
    matches = []

    check_id = (finding.get('check_id') or finding.get('finding_id') or '').lower()
    title = (finding.get('title') or finding.get('check_title') or '').lower()
    description = (finding.get('description') or '').lower()
    resource_type = (finding.get('resource_type') or '').lower().replace(' ', '').replace('-', '').replace('_', '')

    # Combine text fields for pattern matching
    searchable_text = f"{check_id} {title} {description}"

    for edge_id, edge_def in EDGE_DEFINITIONS.items():
        # Check resource type match
        type_match = False
        for valid_type in edge_def['resource_types']:
            normalized_valid = valid_type.lower().replace(' ', '').replace('-', '').replace('_', '')
            if normalized_valid in resource_type or resource_type in normalized_valid:
                type_match = True
                break

        if not type_match:
            continue

        # Check pattern match
        pattern_match = False
        for pattern in edge_def['check_patterns']:
            if re.search(pattern, searchable_text, re.IGNORECASE):
                pattern_match = True
                break

        if not pattern_match:
            continue

        # Found a match - create edge instance
        edge_instance = {
            'edge_id': edge_id,
            'edge_def': edge_def,
            'finding_id': finding.get('id'),
            'resource_id': finding.get('resource_id'),
            'resource_name': finding.get('resource_name'),
            'region': finding.get('region'),
            'account_id': finding.get('account_id'),
        }
        matches.append(edge_instance)

    return matches


def get_entry_point_edges(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Get all edges that represent entry points (where attacks can start)."""
    entry_edges = []

    for finding in findings:
        edges = find_matching_edges(finding)
        for edge in edges:
            if edge['edge_def'].get('entry_point_type'):
                entry_edges.append(edge)

    return entry_edges


def get_edges_by_target(findings: List[Dict[str, Any]], target_type: str) -> List[Dict[str, Any]]:
    """Get all edges that lead to a specific target type."""
    target_edges = []

    for finding in findings:
        edges = find_matching_edges(finding)
        for edge in edges:
            if target_type in edge['edge_def'].get('target_types', []):
                target_edges.append(edge)

    return target_edges


def generate_poc_command(edge: Dict[str, Any]) -> Optional[str]:
    """Generate a PoC command for an edge using its template and resource info."""
    template = edge['edge_def'].get('poc_template')
    if not template:
        return None

    # Replace placeholders with actual values
    replacements = {
        '{bucket_name}': edge.get('resource_name') or edge.get('resource_id') or 'BUCKET_NAME',
        '{function_name}': edge.get('resource_name') or edge.get('resource_id') or 'FUNCTION_NAME',
        '{instance_id}': edge.get('resource_id') or 'INSTANCE_ID',
        '{sg_id}': edge.get('resource_id') or 'SG_ID',
        '{user_name}': edge.get('resource_name') or 'USER_NAME',
        '{role_arn}': edge.get('resource_id') or 'ROLE_ARN',
        '{db_id}': edge.get('resource_id') or 'DB_INSTANCE_ID',
        '{key_id}': edge.get('resource_id') or 'KEY_ID',
        '{volume_id}': edge.get('resource_id') or 'VOLUME_ID',
        '{snapshot_id}': edge.get('resource_id') or 'SNAPSHOT_ID',
        '{public_ip}': 'PUBLIC_IP',  # Would need to look this up
    }

    command = template
    for placeholder, value in replacements.items():
        command = command.replace(placeholder, value)

    return command
