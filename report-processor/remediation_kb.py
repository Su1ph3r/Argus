#!/usr/bin/env python3
"""
Remediation Knowledge Base and AWS CLI PoC Verification Commands

This module provides:
1. Standard remediation guidance for common AWS security findings
2. AWS CLI commands to verify/prove findings (PoC)
3. Description templates for findings with missing descriptions
"""

# Remediation templates for common finding categories
REMEDIATION_KB = {
    # CloudTrail
    "cloudtrail": {
        "not-configured": {
            "description": "AWS CloudTrail is not enabled in this region. CloudTrail provides event history of AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services.",
            "remediation": """1. Open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/
2. Choose "Create trail"
3. Enter a trail name and choose an S3 bucket for log storage
4. Enable "Log file SSE-KMS encryption" for security
5. Enable "CloudWatch Logs" for real-time monitoring
6. Enable for all regions to ensure comprehensive logging

AWS CLI:
aws cloudtrail create-trail --name <trail-name> --s3-bucket-name <bucket-name> --is-multi-region-trail --enable-log-file-validation
aws cloudtrail start-logging --name <trail-name>""",
            "poc_command": 'aws cloudtrail describe-trails --query "trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled]" --output table',
        },
        "no-global-services-logging": {
            "description": "CloudTrail is not logging global service events (IAM, STS, CloudFront). This means critical identity and access management actions are not being recorded.",
            "remediation": """1. Open CloudTrail console
2. Select the trail
3. Under "Additional settings", enable "Include global service events"

AWS CLI:
aws cloudtrail update-trail --name <trail-name> --include-global-service-events""",
            "poc_command": 'aws cloudtrail describe-trails --query "trailList[*].[Name,IncludeGlobalServiceEvents]" --output table',
        },
    },
    # EC2 Security Groups
    "security-group": {
        "opens-all-ports": {
            "description": "Security group allows inbound traffic on all ports (0-65535) from the internet (0.0.0.0/0 or ::/0). This exposes all services running on associated instances to potential attacks.",
            "remediation": """1. Open EC2 console > Security Groups
2. Select the security group
3. Edit inbound rules
4. Remove rules allowing 0.0.0.0/0 or ::/0 on all ports
5. Add specific rules for only required ports and source IPs

AWS CLI:
aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]""",
            "poc_command": "aws ec2 describe-security-groups --group-ids {resource_id} --query \"SecurityGroups[*].IpPermissions[?IpProtocol=='-1']\" --output json",
        },
        "opens-ssh-port": {
            "description": "Security group allows SSH (port 22) access from the internet (0.0.0.0/0 or ::/0). This exposes the SSH service to brute force attacks and vulnerability exploits.",
            "remediation": """1. Open EC2 console > Security Groups
2. Select the security group
3. Edit inbound rules
4. Modify SSH rule to restrict source to specific IPs (bastion host, VPN, or your IP)
5. Consider using AWS Systems Manager Session Manager instead of direct SSH

AWS CLI:
aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr <your-ip>/32""",
            "poc_command": 'aws ec2 describe-security-groups --group-ids {resource_id} --query "SecurityGroups[*].IpPermissions[?FromPort==`22`]" --output json',
        },
        "opens-rdp-port": {
            "description": "Security group allows RDP (port 3389) access from the internet (0.0.0.0/0 or ::/0). This exposes Windows Remote Desktop to brute force attacks.",
            "remediation": """1. Restrict RDP access to specific IPs only
2. Use VPN or AWS Systems Manager for remote access
3. Enable Network Level Authentication (NLA) on Windows instances

AWS CLI:
aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr 0.0.0.0/0""",
            "poc_command": 'aws ec2 describe-security-groups --group-ids {resource_id} --query "SecurityGroups[*].IpPermissions[?FromPort==`3389`]" --output json',
        },
        "opens-mysql-port": {
            "description": "Security group allows MySQL (port 3306) access from the internet. Database ports should never be directly exposed to the internet.",
            "remediation": """1. Remove public access to port 3306
2. Use private subnets for databases
3. Access database only from application tier security groups

AWS CLI:
aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3306 --cidr 0.0.0.0/0""",
            "poc_command": 'aws ec2 describe-security-groups --group-ids {resource_id} --query "SecurityGroups[*].IpPermissions[?FromPort==`3306`]" --output json',
        },
        "opens-postgresql-port": {
            "description": "Security group allows PostgreSQL (port 5432) access from the internet. Database ports should never be directly exposed to the internet.",
            "remediation": """1. Remove public access to port 5432
2. Use private subnets for databases
3. Access database only from application tier security groups

AWS CLI:
aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 5432 --cidr 0.0.0.0/0""",
            "poc_command": 'aws ec2 describe-security-groups --group-ids {resource_id} --query "SecurityGroups[*].IpPermissions[?FromPort==`5432`]" --output json',
        },
        "default-with-rules": {
            "description": "The default security group has non-default inbound or outbound rules. Best practice is to not use default security groups and keep them empty.",
            "remediation": '''1. Create custom security groups with specific rules
2. Remove all inbound/outbound rules from default security group
3. Update resources to use custom security groups

AWS CLI (to view rules):
aws ec2 describe-security-groups --filters "Name=group-name,Values=default" --query "SecurityGroups[*].[VpcId,IpPermissions,IpPermissionsEgress]"''',
            "poc_command": 'aws ec2 describe-security-groups --group-ids {resource_id} --query "SecurityGroups[*].[GroupName,IpPermissions,IpPermissionsEgress]" --output json',
        },
    },
    # IAM
    "iam": {
        "root-mfa": {
            "description": "The AWS root account does not have Multi-Factor Authentication (MFA) enabled. The root account has unrestricted access to all resources and should be protected with MFA.",
            "remediation": """1. Sign in to AWS as root user
2. Go to IAM console > Dashboard
3. Under "Security recommendations", activate MFA for root account
4. Choose virtual MFA device or hardware MFA
5. Complete MFA setup

Note: Use AWS Organizations SCPs to restrict root account usage""",
            "poc_command": 'aws iam get-account-summary --query "SummaryMap.AccountMFAEnabled"',
        },
        "root-access-key": {
            "description": "The root account has active access keys. Root access keys should be deleted as they provide unrestricted programmatic access to the entire AWS account.",
            "remediation": """1. Sign in as root user
2. Go to Security Credentials page
3. Delete all access keys
4. Create IAM users with appropriate permissions for programmatic access

CRITICAL: Before deleting, ensure no automation depends on these keys""",
            "poc_command": 'aws iam get-account-summary --query "SummaryMap.AccountAccessKeysPresent"',
        },
        "root-used-recently": {
            "description": "The root account has been used recently. Best practice is to avoid using the root account for day-to-day activities.",
            "remediation": """1. Create IAM admin users with appropriate permissions
2. Use IAM users for all daily operations
3. Reserve root account for account-level tasks only
4. Enable MFA on root account
5. Set up CloudTrail alerts for root account usage""",
            "poc_command": 'aws iam get-user 2>&1 || echo "Root account - check last activity in IAM console"',
        },
        "password-policy": {
            "description": "The IAM password policy does not meet security best practices. Weak password policies allow users to create easily guessable passwords.",
            "remediation": """Set a strong password policy:
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-symbols \\
  --require-numbers \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24""",
            "poc_command": "aws iam get-account-password-policy --output json",
        },
    },
    # S3
    "s3": {
        "public-access": {
            "description": "S3 bucket allows public access. Public buckets can expose sensitive data to the internet.",
            "remediation": """1. Enable S3 Block Public Access at account level:
aws s3control put-public-access-block --account-id <account-id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

2. Enable on specific bucket:
aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true""",
            "poc_command": 'aws s3api get-public-access-block --bucket {resource_id} --output json 2>&1 || echo "Public access block not configured"',
        },
        "no-encryption": {
            "description": "S3 bucket does not have default encryption enabled. Data stored in the bucket may not be encrypted at rest.",
            "remediation": """Enable default encryption:
aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

Or use KMS:
aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<key-id>"}}]}'
""",
            "poc_command": 'aws s3api get-bucket-encryption --bucket {resource_id} --output json 2>&1 || echo "Encryption not configured"',
        },
        "no-versioning": {
            "description": "S3 bucket does not have versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered.",
            "remediation": """Enable versioning:
aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled""",
            "poc_command": "aws s3api get-bucket-versioning --bucket {resource_id} --output json",
        },
        "no-logging": {
            "description": "S3 bucket access logging is not enabled. Without logging, access to the bucket is not tracked.",
            "remediation": """Enable access logging:
1. Create a logging bucket
2. Enable logging:
aws s3api put-bucket-logging --bucket <bucket-name> --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<logging-bucket>","TargetPrefix":"<prefix>/"}}'
""",
            "poc_command": "aws s3api get-bucket-logging --bucket {resource_id} --output json",
        },
        "no-https": {
            "description": "S3 bucket policy does not enforce HTTPS. Data could be transmitted in clear text.",
            "remediation": """Add bucket policy to enforce HTTPS:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowSSLRequestsOnly",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}""",
            "poc_command": 'aws s3api get-bucket-policy --bucket {resource_id} --output json 2>&1 || echo "No bucket policy"',
        },
    },
    # EBS
    "ebs": {
        "not-encrypted": {
            "description": "EBS volume is not encrypted. Data at rest is not protected and could be exposed if the underlying storage is compromised.",
            "remediation": """EBS volumes cannot be encrypted in place. To encrypt:
1. Create a snapshot of the volume
2. Copy the snapshot with encryption enabled
3. Create new volume from encrypted snapshot
4. Replace the original volume

Enable default encryption for new volumes:
aws ec2 enable-ebs-encryption-by-default --region <region>""",
            "poc_command": 'aws ec2 describe-volumes --volume-ids {resource_id} --query "Volumes[*].[VolumeId,Encrypted,KmsKeyId]" --output table',
        },
    },
    # RDS
    "rds": {
        "not-encrypted": {
            "description": "RDS instance storage is not encrypted. Database data at rest is not protected.",
            "remediation": """RDS encryption must be enabled at creation time. To encrypt existing database:
1. Create a snapshot of the database
2. Copy snapshot with encryption enabled
3. Restore from encrypted snapshot
4. Update application connection strings""",
            "poc_command": 'aws rds describe-db-instances --db-instance-identifier {resource_id} --query "DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId]" --output table',
        },
        "publicly-accessible": {
            "description": "RDS instance is publicly accessible. Database should not be directly accessible from the internet.",
            "remediation": """1. Modify RDS instance:
aws rds modify-db-instance --db-instance-identifier <db-id> --no-publicly-accessible --apply-immediately

2. Ensure RDS is in a private subnet
3. Access via bastion host or VPN only""",
            "poc_command": 'aws rds describe-db-instances --db-instance-identifier {resource_id} --query "DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible,Endpoint.Address]" --output table',
        },
        "no-backup": {
            "description": "RDS automated backups are disabled. Database recovery may not be possible in case of failure.",
            "remediation": """Enable automated backups:
aws rds modify-db-instance --db-instance-identifier <db-id> --backup-retention-period 7 --preferred-backup-window "03:00-04:00" --apply-immediately""",
            "poc_command": 'aws rds describe-db-instances --db-instance-identifier {resource_id} --query "DBInstances[*].[DBInstanceIdentifier,BackupRetentionPeriod]" --output table',
        },
    },
    # Lambda
    "lambda": {
        "secrets-in-env": {
            "description": "Lambda function has secrets/credentials stored in environment variables. Secrets in plain text can be exposed through console access, CLI, or logs.",
            "remediation": """1. Remove secrets from environment variables
2. Use AWS Secrets Manager:
   - Store secret: aws secretsmanager create-secret --name <name> --secret-string <value>
   - Access in Lambda: boto3.client('secretsmanager').get_secret_value(SecretId='<name>')
3. Or use Parameter Store:
   - Store: aws ssm put-parameter --name <name> --value <value> --type SecureString
   - Access: boto3.client('ssm').get_parameter(Name='<name>', WithDecryption=True)""",
            "poc_command": 'aws lambda get-function-configuration --function-name {resource_id} --query "Environment.Variables" --output json',
        },
        "public-access": {
            "description": "Lambda function has a resource policy that allows public invocation. Anyone can execute the function.",
            "remediation": """Review and update resource policy:
1. View policy: aws lambda get-policy --function-name <function-name>
2. Remove public access: aws lambda remove-permission --function-name <function-name> --statement-id <statement-id>
3. Add specific principal: aws lambda add-permission --function-name <function-name> --statement-id <id> --action lambda:InvokeFunction --principal <account-id>""",
            "poc_command": 'aws lambda get-policy --function-name {resource_id} --output json 2>&1 || echo "No resource policy"',
        },
    },
    # VPC
    "vpc": {
        "flow-logs-disabled": {
            "description": "VPC Flow Logs are not enabled. Network traffic to and from the VPC is not being logged, hindering incident investigation.",
            "remediation": """Enable VPC Flow Logs:
aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name <log-group> --deliver-logs-permission-arn <iam-role-arn>

Or to S3:
aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type s3 --log-destination <s3-bucket-arn>""",
            "poc_command": 'aws ec2 describe-flow-logs --filter "Name=resource-id,Values={resource_id}" --output json',
        },
        "nacl-allow-all": {
            "description": "Network ACL allows all traffic. NACLs should be configured to allow only necessary traffic as a defense-in-depth measure.",
            "remediation": """1. Review and restrict NACL rules
2. Deny all traffic by default
3. Add specific allow rules for required ports and CIDR blocks

View NACL:
aws ec2 describe-network-acls --network-acl-ids <nacl-id>""",
            "poc_command": 'aws ec2 describe-network-acls --network-acl-ids {resource_id} --query "NetworkAcls[*].Entries" --output json',
        },
    },
}


def get_remediation(finding_type: str, check_id: str) -> dict:
    """
    Get remediation data for a finding type and check ID.
    Returns dict with 'description', 'remediation', 'poc_command'
    """
    # Normalize finding_type and check_id
    finding_type = finding_type.lower().replace(" ", "-").replace("_", "-")
    check_id = check_id.lower().replace(" ", "-").replace("_", "-")

    # Try to find matching category
    for category, checks in REMEDIATION_KB.items():
        if category in finding_type or category in check_id:
            # Try to find matching check
            for check_name, data in checks.items():
                if check_name in check_id or check_name in finding_type:
                    return data

    return None


def get_poc_command(finding_type: str, check_id: str, resource_id: str = None) -> str:
    """
    Get AWS CLI command to verify a finding.
    Returns the command with resource_id substituted if provided.

    Security: resource_id is validated and quoted to prevent command injection.
    """
    import re
    import shlex

    data = get_remediation(finding_type, check_id)
    if data and "poc_command" in data:
        cmd = data["poc_command"]
        if resource_id:
            # Validate resource_id matches AWS resource patterns
            if not re.match(r"^[a-zA-Z0-9\-\_:/.@]+$", resource_id):
                return None  # Invalid resource ID format
            # Use shlex.quote for safe shell escaping when command is executed
            safe_resource_id = shlex.quote(resource_id)
            # Remove surrounding quotes since we're building a command list
            if safe_resource_id.startswith("'") and safe_resource_id.endswith("'"):
                safe_resource_id = safe_resource_id[1:-1]
            cmd = cmd.format(resource_id=safe_resource_id)
        return cmd
    return None


def get_default_remediation(service: str, description: str) -> str:
    """
    Generate a generic remediation based on service type.
    """
    generic_remediations = {
        "cloudtrail": "Enable CloudTrail logging for this region. See AWS CloudTrail documentation for configuration steps.",
        "ec2": "Review EC2 security group rules and restrict access to only necessary ports and IP ranges.",
        "iam": "Review IAM policies and follow the principle of least privilege. Enable MFA for all users.",
        "s3": "Enable S3 Block Public Access, encryption, versioning, and logging for all buckets.",
        "rds": "Enable RDS encryption, automated backups, and ensure instances are in private subnets.",
        "lambda": "Review Lambda function permissions and environment variables. Use Secrets Manager for sensitive data.",
        "vpc": "Enable VPC Flow Logs and review Network ACL/Security Group rules.",
    }

    for svc, remediation in generic_remediations.items():
        if svc in service.lower():
            return remediation

    return "Review the finding and implement appropriate security controls based on AWS security best practices."


def get_default_description(service: str, check_id: str, existing_description: str) -> str:
    """
    Enhance or generate a description for a finding.
    """
    if (
        existing_description
        and len(existing_description) > 50
        and "no description" not in existing_description.lower()
    ):
        return existing_description

    data = get_remediation(service, check_id)
    if data and "description" in data:
        return data["description"]

    # Generate generic description
    check_title = check_id.replace("-", " ").replace("_", " ").title()
    return f"Security finding detected: {check_title}. Review and remediate according to AWS security best practices."
