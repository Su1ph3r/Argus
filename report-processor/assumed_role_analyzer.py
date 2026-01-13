#!/usr/bin/env python3
"""
Assumed Role Analyzer

Discovers IAM role assumption relationships by:
1. Loading IAM role findings from the database
2. Parsing trust policies to identify who can assume each role
3. Extracting source principals (users, roles, services, accounts)
4. Identifying cross-account access and external ID requirements
5. Calculating risk levels based on exposure
6. Saving mappings to the assumed_role_mappings table
"""

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field

import psycopg2
from psycopg2.extras import Json

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Principal type mappings
PRINCIPAL_TYPE_MAP = {
    "user": "IAM User",
    "role": "IAM Role",
    "root": "Root Account",
    "assumed-role": "Assumed Role",
    "federated-user": "Federated User",
    "service": "AWS Service",
    "account": "AWS Account",
}

# AWS service principals
AWS_SERVICES = {
    "ec2.amazonaws.com": "EC2",
    "lambda.amazonaws.com": "Lambda",
    "ecs.amazonaws.com": "ECS",
    "ecs-tasks.amazonaws.com": "ECS Tasks",
    "eks.amazonaws.com": "EKS",
    "codebuild.amazonaws.com": "CodeBuild",
    "codepipeline.amazonaws.com": "CodePipeline",
    "cloudformation.amazonaws.com": "CloudFormation",
    "s3.amazonaws.com": "S3",
    "sns.amazonaws.com": "SNS",
    "sqs.amazonaws.com": "SQS",
    "events.amazonaws.com": "EventBridge",
    "states.amazonaws.com": "Step Functions",
    "ssm.amazonaws.com": "Systems Manager",
    "config.amazonaws.com": "Config",
    "guardduty.amazonaws.com": "GuardDuty",
    "securityhub.amazonaws.com": "Security Hub",
    "logs.amazonaws.com": "CloudWatch Logs",
    "firehose.amazonaws.com": "Kinesis Firehose",
    "glue.amazonaws.com": "Glue",
    "sagemaker.amazonaws.com": "SageMaker",
    "apigateway.amazonaws.com": "API Gateway",
    "elasticmapreduce.amazonaws.com": "EMR",
    "rds.amazonaws.com": "RDS",
    "redshift.amazonaws.com": "Redshift",
    "backup.amazonaws.com": "Backup",
    "autoscaling.amazonaws.com": "Auto Scaling",
    "elasticloadbalancing.amazonaws.com": "ELB",
    "monitoring.amazonaws.com": "CloudWatch",
}


@dataclass
class AssumedRoleMapping:
    """Represents an assumed role mapping."""

    mapping_id: str
    cloud_provider: str
    account_id: str | None
    source_principal_type: str
    source_principal_arn: str | None
    source_principal_name: str
    source_account_id: str | None
    target_role_arn: str
    target_role_name: str
    target_account_id: str | None
    trust_policy: dict
    conditions: dict | None
    is_cross_account: bool
    is_external_id_required: bool
    external_id_value: str | None
    max_session_duration: int | None
    assumption_chain_depth: int
    risk_level: str


class AssumedRoleAnalyzer:
    """Analyzes IAM role trust policies to discover role assumption relationships."""

    def __init__(self):
        db_password = os.environ.get("DB_PASSWORD")
        if not db_password:
            db_password = os.environ.get("POSTGRES_PASSWORD", "")

        self.db_config = {
            "host": os.environ.get("DB_HOST", "postgresql"),
            "database": os.environ.get("DB_NAME", "security_audits"),
            "user": os.environ.get("DB_USER", "auditor"),
            "password": db_password,
        }

        self.findings: list[dict] = []
        self.discovered_mappings: list[AssumedRoleMapping] = []
        self.processed_roles: set[str] = set()

    def connect_db(self):
        """Connect to PostgreSQL database."""
        try:
            return psycopg2.connect(**self.db_config)
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return None

    def load_findings(self, scan_id: str | None = None) -> list[dict]:
        """Load IAM role findings from database."""
        conn = self.connect_db()
        if not conn:
            return []

        try:
            cur = conn.cursor()

            # Query findings related to IAM roles and trust policies
            query = """
                SELECT id, finding_id, tool, cloud_provider, account_id, region,
                       resource_type, resource_id, resource_name, severity, status,
                       title, description, metadata
                FROM findings
                WHERE cloud_provider = 'aws'
                AND (
                    resource_type ILIKE '%role%'
                    OR resource_type ILIKE 'AwsIamRole'
                    OR resource_type ILIKE 'AWS::IAM::Role'
                    OR title ILIKE '%role%trust%'
                    OR title ILIKE '%assume%role%'
                    OR title ILIKE '%trust policy%'
                    OR title ILIKE '%cross.account%'
                    OR finding_id ILIKE '%iam%role%'
                    OR finding_id ILIKE '%trust%'
                )
            """
            params = []

            if scan_id:
                query += " AND scan_id = %s"
                params.append(scan_id)

            query += " ORDER BY severity DESC"

            cur.execute(query, params)
            columns = [desc[0] for desc in cur.description]
            findings = [dict(zip(columns, row, strict=False)) for row in cur.fetchall()]

            logger.info(f"Loaded {len(findings)} IAM role findings from database")
            self.findings = findings
            return findings

        except Exception as e:
            logger.error(f"Error loading findings: {e}")
            return []
        finally:
            conn.close()

    def analyze_findings(self) -> list[AssumedRoleMapping]:
        """Analyze findings to discover role assumption mappings."""
        logger.info("Analyzing IAM role findings for assumed role mappings...")

        self.discovered_mappings = []
        self.processed_roles = set()

        for finding in self.findings:
            mappings = self._extract_mappings_from_finding(finding)
            self.discovered_mappings.extend(mappings)

        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.discovered_mappings.sort(
            key=lambda m: risk_order.get(m.risk_level, 4)
        )

        logger.info(f"Discovered {len(self.discovered_mappings)} role assumption mappings")
        return self.discovered_mappings

    def _extract_mappings_from_finding(self, finding: dict) -> list[AssumedRoleMapping]:
        """Extract role assumption mappings from a single finding."""
        mappings = []
        metadata = finding.get("metadata") or {}

        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {}

        # Extract role ARN
        role_arn = self._extract_role_arn(finding, metadata)
        if not role_arn:
            return mappings

        # Skip if already processed
        if role_arn in self.processed_roles:
            return mappings
        self.processed_roles.add(role_arn)

        # Extract role name and account
        role_name = self._extract_role_name(role_arn, finding)
        target_account_id = self._extract_account_from_arn(role_arn) or finding.get("account_id")

        # Extract trust policy
        trust_policy = self._extract_trust_policy(finding, metadata)
        if not trust_policy:
            return mappings

        # Parse trust policy statements
        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            # Only process Allow statements for sts:AssumeRole
            effect = statement.get("Effect", "")
            if effect.lower() != "allow":
                continue

            action = statement.get("Action", [])
            if isinstance(action, str):
                action = [action]

            # Check for assume role actions
            assume_actions = [
                a for a in action
                if "AssumeRole" in a or "sts:*" in a or a == "*"
            ]
            if not assume_actions:
                continue

            # Extract principals from statement
            principal_mappings = self._extract_principals_from_statement(
                statement, finding, role_arn, role_name, target_account_id, trust_policy
            )
            mappings.extend(principal_mappings)

        return mappings

    def _extract_principals_from_statement(
        self,
        statement: dict,
        finding: dict,
        role_arn: str,
        role_name: str,
        target_account_id: str | None,
        trust_policy: dict,
    ) -> list[AssumedRoleMapping]:
        """Extract principal information from a trust policy statement."""
        mappings = []
        principal = statement.get("Principal", {})
        conditions = statement.get("Condition", {})

        # Handle Principal: "*" (anyone can assume)
        if principal == "*":
            mapping = self._create_mapping(
                source_type="Any Principal",
                source_arn="*",
                source_name="Any Principal (Public)",
                source_account=None,
                role_arn=role_arn,
                role_name=role_name,
                target_account=target_account_id,
                trust_policy=trust_policy,
                conditions=conditions,
                finding=finding,
            )
            mappings.append(mapping)
            return mappings

        if not isinstance(principal, dict):
            return mappings

        # Process AWS principals
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]

        for aws_principal in aws_principals:
            if aws_principal == "*":
                mapping = self._create_mapping(
                    source_type="Any AWS Principal",
                    source_arn="*",
                    source_name="Any AWS Principal",
                    source_account=None,
                    role_arn=role_arn,
                    role_name=role_name,
                    target_account=target_account_id,
                    trust_policy=trust_policy,
                    conditions=conditions,
                    finding=finding,
                )
                mappings.append(mapping)
            else:
                mapping = self._parse_aws_principal(
                    aws_principal, role_arn, role_name, target_account_id,
                    trust_policy, conditions, finding
                )
                if mapping:
                    mappings.append(mapping)

        # Process Service principals
        service_principals = principal.get("Service", [])
        if isinstance(service_principals, str):
            service_principals = [service_principals]

        for service in service_principals:
            service_name = AWS_SERVICES.get(service, service.split(".")[0].upper())
            mapping = self._create_mapping(
                source_type="AWS Service",
                source_arn=f"arn:aws:iam::aws:service/{service}",
                source_name=service_name,
                source_account="aws",
                role_arn=role_arn,
                role_name=role_name,
                target_account=target_account_id,
                trust_policy=trust_policy,
                conditions=conditions,
                finding=finding,
            )
            mappings.append(mapping)

        # Process Federated principals
        federated_principals = principal.get("Federated", [])
        if isinstance(federated_principals, str):
            federated_principals = [federated_principals]

        for federated in federated_principals:
            fed_name = federated.split("/")[-1] if "/" in federated else federated
            mapping = self._create_mapping(
                source_type="Federated Identity",
                source_arn=federated,
                source_name=fed_name,
                source_account=None,
                role_arn=role_arn,
                role_name=role_name,
                target_account=target_account_id,
                trust_policy=trust_policy,
                conditions=conditions,
                finding=finding,
            )
            mappings.append(mapping)

        return mappings

    def _parse_aws_principal(
        self,
        principal: str,
        role_arn: str,
        role_name: str,
        target_account_id: str | None,
        trust_policy: dict,
        conditions: dict,
        finding: dict,
    ) -> AssumedRoleMapping | None:
        """Parse an AWS principal ARN and create a mapping."""
        # Handle account ID only (arn:aws:iam::123456789012:root)
        if re.match(r"^\d{12}$", principal):
            return self._create_mapping(
                source_type="AWS Account",
                source_arn=f"arn:aws:iam::{principal}:root",
                source_name=f"Account {principal}",
                source_account=principal,
                role_arn=role_arn,
                role_name=role_name,
                target_account=target_account_id,
                trust_policy=trust_policy,
                conditions=conditions,
                finding=finding,
            )

        # Parse ARN
        arn_match = re.match(
            r"arn:aws:iam::(\d{12}):(\w+)/?(.*)?", principal
        )
        if not arn_match:
            # Try STS ARN pattern
            arn_match = re.match(
                r"arn:aws:sts::(\d{12}):(\w+)/?(.*)?", principal
            )

        if arn_match:
            account_id = arn_match.group(1)
            resource_type = arn_match.group(2)
            resource_name = arn_match.group(3) or resource_type

            principal_type = PRINCIPAL_TYPE_MAP.get(resource_type, resource_type)

            return self._create_mapping(
                source_type=principal_type,
                source_arn=principal,
                source_name=resource_name,
                source_account=account_id,
                role_arn=role_arn,
                role_name=role_name,
                target_account=target_account_id,
                trust_policy=trust_policy,
                conditions=conditions,
                finding=finding,
            )

        # Handle root account pattern
        if ":root" in principal:
            account_match = re.search(r"::(\d{12}):", principal)
            if account_match:
                account_id = account_match.group(1)
                return self._create_mapping(
                    source_type="Root Account",
                    source_arn=principal,
                    source_name=f"Root ({account_id})",
                    source_account=account_id,
                    role_arn=role_arn,
                    role_name=role_name,
                    target_account=target_account_id,
                    trust_policy=trust_policy,
                    conditions=conditions,
                    finding=finding,
                )

        return None

    def _create_mapping(
        self,
        source_type: str,
        source_arn: str | None,
        source_name: str,
        source_account: str | None,
        role_arn: str,
        role_name: str,
        target_account: str | None,
        trust_policy: dict,
        conditions: dict,
        finding: dict,
    ) -> AssumedRoleMapping:
        """Create an AssumedRoleMapping object."""
        # Determine if cross-account
        is_cross_account = False
        if source_account and target_account:
            is_cross_account = source_account != target_account
        elif source_account == "*" or source_arn == "*":
            is_cross_account = True

        # Check for external ID requirement
        is_external_id_required = False
        external_id_value = None
        if conditions:
            string_equals = conditions.get("StringEquals", {})
            if "sts:ExternalId" in string_equals:
                is_external_id_required = True
                external_id_value = string_equals.get("sts:ExternalId")
                if isinstance(external_id_value, list):
                    external_id_value = external_id_value[0] if external_id_value else None

        # Calculate risk level
        risk_level = self._calculate_risk_level(
            source_type, source_arn, is_cross_account,
            is_external_id_required, conditions
        )

        # Generate unique mapping ID
        mapping_content = f"{source_arn}:{role_arn}"
        mapping_id = hashlib.md5(mapping_content.encode()).hexdigest()[:16]

        return AssumedRoleMapping(
            mapping_id=mapping_id,
            cloud_provider="aws",
            account_id=finding.get("account_id"),
            source_principal_type=source_type,
            source_principal_arn=source_arn,
            source_principal_name=source_name,
            source_account_id=source_account,
            target_role_arn=role_arn,
            target_role_name=role_name,
            target_account_id=target_account,
            trust_policy=trust_policy,
            conditions=conditions if conditions else None,
            is_cross_account=is_cross_account,
            is_external_id_required=is_external_id_required,
            external_id_value=external_id_value,
            max_session_duration=None,
            assumption_chain_depth=1,
            risk_level=risk_level,
        )

    def _calculate_risk_level(
        self,
        source_type: str,
        source_arn: str | None,
        is_cross_account: bool,
        is_external_id_required: bool,
        conditions: dict | None,
    ) -> str:
        """Calculate risk level for a role assumption mapping."""
        # Critical: Public access (anyone can assume)
        if source_arn == "*" or source_type in ["Any Principal", "Any AWS Principal"]:
            if not conditions:
                return "critical"
            # With conditions, still high risk
            return "high"

        # High: Cross-account without external ID
        if is_cross_account and not is_external_id_required:
            return "high"

        # Medium: Cross-account with external ID, or service principals without conditions
        if is_cross_account and is_external_id_required:
            return "medium"

        if source_type == "AWS Service" and not conditions:
            return "medium"

        # Low: Same account with proper controls
        return "low"

    def _extract_role_arn(self, finding: dict, metadata: dict) -> str | None:
        """Extract role ARN from finding."""
        # Try resource_id first
        resource_id = finding.get("resource_id", "")
        if resource_id and "arn:aws:iam" in resource_id and "role" in resource_id.lower():
            return resource_id

        # Check metadata for ARN
        if metadata:
            for key in ["arn", "resource_arn", "RoleArn", "role_arn", "Arn"]:
                if key in metadata:
                    arn = metadata[key]
                    if arn and "role" in arn.lower():
                        return arn

            # Check nested structures
            for key in ["resource", "Resource", "role", "Role"]:
                if key in metadata and isinstance(metadata[key], dict):
                    nested = metadata[key]
                    for arn_key in ["arn", "Arn", "ARN"]:
                        if arn_key in nested:
                            return nested[arn_key]

        return None

    def _extract_role_name(self, role_arn: str, finding: dict) -> str:
        """Extract role name from ARN or finding."""
        # Extract from ARN
        if role_arn:
            match = re.search(r":role/(.+)$", role_arn)
            if match:
                return match.group(1)

        # Fall back to resource_name
        return finding.get("resource_name", "Unknown Role")

    def _extract_account_from_arn(self, arn: str) -> str | None:
        """Extract account ID from ARN."""
        if not arn:
            return None
        match = re.search(r"::(\d{12}):", arn)
        return match.group(1) if match else None

    def _extract_trust_policy(self, finding: dict, metadata: dict) -> dict | None:
        """Extract trust policy from finding metadata."""
        # Direct trust policy in metadata
        for key in [
            "trust_policy", "TrustPolicy", "AssumeRolePolicyDocument",
            "assume_role_policy_document", "assumeRolePolicyDocument",
            "trust_relationship", "TrustRelationship"
        ]:
            if key in metadata:
                policy = metadata[key]
                if isinstance(policy, str):
                    try:
                        return json.loads(policy)
                    except json.JSONDecodeError:
                        continue
                elif isinstance(policy, dict):
                    return policy

        # Check nested in resource details
        for container_key in ["resource", "Resource", "role", "Role", "detail", "Detail"]:
            if container_key in metadata and isinstance(metadata[container_key], dict):
                container = metadata[container_key]
                for key in [
                    "AssumeRolePolicyDocument", "trust_policy",
                    "TrustPolicy", "assumeRolePolicyDocument"
                ]:
                    if key in container:
                        policy = container[key]
                        if isinstance(policy, str):
                            try:
                                return json.loads(policy)
                            except json.JSONDecodeError:
                                continue
                        elif isinstance(policy, dict):
                            return policy

        # Try parsing from description (some tools include it)
        description = finding.get("description", "")
        if "Principal" in description and "Statement" in description:
            try:
                # Find JSON in description
                start = description.find("{")
                end = description.rfind("}") + 1
                if start >= 0 and end > start:
                    return json.loads(description[start:end])
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    def save_mappings(self, scan_id: str | None = None) -> int:
        """Save discovered mappings to database."""
        conn = self.connect_db()
        if not conn:
            return 0

        saved_count = 0
        try:
            cur = conn.cursor()

            for mapping in self.discovered_mappings:
                try:
                    cur.execute(
                        """
                        INSERT INTO assumed_role_mappings (
                            mapping_id, scan_id, cloud_provider, account_id,
                            source_principal_type, source_principal_arn, source_principal_name,
                            source_account_id, target_role_arn, target_role_name, target_account_id,
                            trust_policy, conditions, is_cross_account, is_external_id_required,
                            external_id_value, max_session_duration, assumption_chain_depth,
                            risk_level, neo4j_synced
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        ON CONFLICT (mapping_id) DO UPDATE SET
                            scan_id = EXCLUDED.scan_id,
                            trust_policy = EXCLUDED.trust_policy,
                            conditions = EXCLUDED.conditions,
                            is_cross_account = EXCLUDED.is_cross_account,
                            is_external_id_required = EXCLUDED.is_external_id_required,
                            risk_level = EXCLUDED.risk_level,
                            updated_at = NOW()
                        """,
                        (
                            mapping.mapping_id,
                            scan_id,
                            mapping.cloud_provider,
                            mapping.account_id,
                            mapping.source_principal_type,
                            mapping.source_principal_arn,
                            mapping.source_principal_name,
                            mapping.source_account_id,
                            mapping.target_role_arn,
                            mapping.target_role_name,
                            mapping.target_account_id,
                            Json(mapping.trust_policy),
                            Json(mapping.conditions) if mapping.conditions else None,
                            mapping.is_cross_account,
                            mapping.is_external_id_required,
                            mapping.external_id_value,
                            mapping.max_session_duration,
                            mapping.assumption_chain_depth,
                            mapping.risk_level,
                            False,  # neo4j_synced
                        ),
                    )
                    saved_count += 1
                except Exception as e:
                    logger.error(f"Error saving mapping {mapping.mapping_id}: {e}")
                    continue

            conn.commit()
            logger.info(f"Saved {saved_count} assumed role mappings to database")

        except Exception as e:
            logger.error(f"Error saving mappings: {e}")
            conn.rollback()
        finally:
            conn.close()

        return saved_count

    def analyze(self, scan_id: str | None = None) -> list[AssumedRoleMapping]:
        """Run full assumed role analysis."""
        logger.info("Starting assumed role analysis...")

        # Load findings
        self.load_findings(scan_id)
        if not self.findings:
            logger.warning("No IAM role findings to analyze")
            return []

        # Analyze findings
        self.analyze_findings()

        # Save to database
        self.save_mappings(scan_id)

        logger.info(f"Assumed role analysis complete. Found {len(self.discovered_mappings)} mappings")
        return self.discovered_mappings

    def get_summary(self) -> dict:
        """Get summary statistics of discovered mappings."""
        if not self.discovered_mappings:
            return {
                "total_mappings": 0,
                "cross_account": 0,
                "external_id_required": 0,
                "by_source_type": {},
                "by_risk": {},
            }

        cross_account = sum(1 for m in self.discovered_mappings if m.is_cross_account)
        external_id = sum(1 for m in self.discovered_mappings if m.is_external_id_required)

        # Count by source type
        source_counts: dict[str, int] = {}
        for mapping in self.discovered_mappings:
            source_type = mapping.source_principal_type
            source_counts[source_type] = source_counts.get(source_type, 0) + 1

        # Count by risk level
        risk_counts: dict[str, int] = {}
        for mapping in self.discovered_mappings:
            risk = mapping.risk_level
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        return {
            "total_mappings": len(self.discovered_mappings),
            "cross_account": cross_account,
            "external_id_required": external_id,
            "by_source_type": source_counts,
            "by_risk": risk_counts,
            "critical_mappings": [
                {
                    "mapping_id": m.mapping_id,
                    "source": m.source_principal_name,
                    "target": m.target_role_name,
                    "is_cross_account": m.is_cross_account,
                }
                for m in self.discovered_mappings
                if m.risk_level == "critical"
            ][:5],
        }


def main():
    """Main entry point for assumed role analysis."""
    analyzer = AssumedRoleAnalyzer()

    # Run analysis
    mappings = analyzer.analyze()

    # Print summary
    summary = analyzer.get_summary()
    print(f"\n{'='*60}")
    print("ASSUMED ROLE ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total role assumption mappings: {summary['total_mappings']}")
    print(f"Cross-account mappings: {summary['cross_account']}")
    print(f"External ID required: {summary['external_id_required']}")

    if summary.get("by_source_type"):
        print("\nBy Source Type:")
        for source_type, count in sorted(summary["by_source_type"].items(), key=lambda x: -x[1]):
            print(f"  {source_type}: {count}")

    if summary.get("by_risk"):
        print("\nBy Risk Level:")
        for risk, count in sorted(
            summary["by_risk"].items(),
            key=lambda x: ["critical", "high", "medium", "low"].index(x[0]) if x[0] in ["critical", "high", "medium", "low"] else 99
        ):
            print(f"  {risk}: {count}")

    if summary.get("critical_mappings"):
        print("\nCritical Risk Mappings:")
        for m in summary["critical_mappings"]:
            cross = " (cross-account)" if m["is_cross_account"] else ""
            print(f"  - {m['source']} -> {m['target']}{cross}")

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
