#!/usr/bin/env python3
"""
Blast Radius Analyzer

Calculates the potential impact of compromised identities by:
1. Querying direct permissions from enumerate_iam_results
2. Traversing role assumption chains from assumed_role_mappings
3. Calculating cross-account scope
4. Aggregating into total_blast_radius metric
5. Assigning risk levels based on thresholds
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime

import psycopg2
from psycopg2.extras import Json, RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Risk level thresholds for blast radius calculation
RISK_THRESHOLDS = {
    "critical": {"resources": 100, "cross_account": True, "admin": True},
    "high": {"resources": 50, "service_wide": True},
    "medium": {"resources": 10},
    "low": {"resources": 0},
}

# High-risk IAM actions that indicate elevated blast radius
HIGH_RISK_ACTIONS = {
    # Admin actions
    "iam:*",
    "iam:CreateRole",
    "iam:CreateUser",
    "iam:CreatePolicy",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    # STS actions
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "sts:GetFederationToken",
    # Data access actions
    "s3:*",
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "dynamodb:*",
    "rds:*",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "kms:Decrypt",
    "kms:Encrypt",
    # Compute actions
    "ec2:RunInstances",
    "lambda:InvokeFunction",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "ecs:RunTask",
    # Org/account actions
    "organizations:*",
    "account:*",
}

# Service categories for grouping permissions
SERVICE_CATEGORIES = {
    "iam": "Identity",
    "sts": "Identity",
    "s3": "Storage",
    "dynamodb": "Database",
    "rds": "Database",
    "ec2": "Compute",
    "lambda": "Compute",
    "ecs": "Compute",
    "eks": "Compute",
    "secretsmanager": "Secrets",
    "ssm": "Management",
    "kms": "Encryption",
    "sns": "Messaging",
    "sqs": "Messaging",
    "cloudwatch": "Monitoring",
    "logs": "Monitoring",
    "cloudtrail": "Audit",
    "config": "Audit",
    "guardduty": "Security",
    "securityhub": "Security",
}


@dataclass
class PermissionBreakdown:
    """Breakdown of permissions by service."""

    service: str
    action_count: int
    resource_count: int
    high_risk_actions: list[str] = field(default_factory=list)


@dataclass
class ReachableRole:
    """A role reachable through assumption chains."""

    role_arn: str
    role_name: str | None
    account_id: str
    is_cross_account: bool
    assumption_depth: int


@dataclass
class BlastRadiusAnalysis:
    """Full blast radius analysis for an identity."""

    analysis_id: str
    identity_arn: str
    identity_type: str
    account_id: str
    direct_permission_count: int = 0
    direct_resource_count: int = 0
    assumable_roles_count: int = 0
    assumption_chain_depth: int = 1
    cross_account_roles_count: int = 0
    affected_accounts: list[str] = field(default_factory=list)
    total_blast_radius: int = 0
    risk_level: str = "medium"
    reachable_resources: list[str] = field(default_factory=list)
    reachable_roles: list[ReachableRole] = field(default_factory=list)
    permission_breakdown: list[PermissionBreakdown] = field(default_factory=list)
    created_at: datetime | None = None


class BlastRadiusAnalyzer:
    """Calculates the blast radius (potential impact) of compromised identities."""

    def __init__(self, db_config: dict | None = None):
        """Initialize analyzer with database configuration."""
        if db_config:
            self.db_config = db_config
        else:
            # Use environment variables for database connection
            db_password = os.environ.get("DB_PASSWORD")
            if not db_password:
                db_password = os.environ.get("POSTGRES_PASSWORD", "")

            self.db_config = {
                "host": os.environ.get("DB_HOST", "postgresql"),
                "database": os.environ.get("DB_NAME", "security_audits"),
                "user": os.environ.get("DB_USER", "auditor"),
                "password": db_password,
            }

        self.analyses: list[BlastRadiusAnalysis] = []

    def _get_connection(self):
        """Get database connection with RealDictCursor."""
        try:
            return psycopg2.connect(**self.db_config, cursor_factory=RealDictCursor)
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return None

    def analyze_identity(self, identity_arn: str, scan_id: str | None = None) -> dict:
        """
        Analyze blast radius for a specific identity.

        Algorithm:
        1. Query direct permissions from enumerate_iam_results
        2. Traverse role assumption chains from assumed_role_mappings
        3. Calculate cross-account scope
        4. Aggregate into total_blast_radius

        Args:
            identity_arn: The ARN of the identity to analyze
            scan_id: Optional scan ID to filter results

        Returns:
            Dictionary containing the blast radius analysis
        """
        logger.info(f"Analyzing blast radius for identity: {identity_arn}")

        # Get direct permissions
        direct_perms = self._get_direct_permissions(identity_arn, scan_id)

        # Get assumable roles
        assumable_roles = self._get_assumable_roles(identity_arn, scan_id)

        # Calculate assumption chain depth and reach
        chain_info = self._calculate_assumption_chain(identity_arn, scan_id=scan_id)

        # Extract identity details
        identity_type = self._determine_identity_type(identity_arn)
        account_id = self._extract_account_from_arn(identity_arn) or "unknown"

        # Calculate permission breakdown by service
        permission_breakdown = self._calculate_permission_breakdown(direct_perms)

        # Collect affected accounts
        affected_accounts = set()
        affected_accounts.add(account_id)
        for role in assumable_roles:
            if role.get("target_account_id"):
                affected_accounts.add(role["target_account_id"])

        # Calculate total blast radius score
        total_blast_radius = self._calculate_blast_radius_score(
            direct_perms=direct_perms,
            assumable_roles=assumable_roles,
            chain_info=chain_info,
            affected_accounts=affected_accounts,
        )

        # Build reachable roles list
        reachable_roles = [
            ReachableRole(
                role_arn=role.get("target_role_arn", ""),
                role_name=role.get("target_role_name"),
                account_id=role.get("target_account_id", ""),
                is_cross_account=role.get("is_cross_account", False),
                assumption_depth=role.get("assumption_chain_depth", 1),
            )
            for role in assumable_roles
        ]

        # Build analysis result
        analysis = BlastRadiusAnalysis(
            analysis_id=self._generate_analysis_id(identity_arn, scan_id),
            identity_arn=identity_arn,
            identity_type=identity_type,
            account_id=account_id,
            direct_permission_count=direct_perms.get("permission_count", 0),
            direct_resource_count=self._count_resources(direct_perms),
            assumable_roles_count=len(assumable_roles),
            assumption_chain_depth=chain_info.get("max_depth", 1),
            cross_account_roles_count=sum(
                1 for r in assumable_roles if r.get("is_cross_account")
            ),
            affected_accounts=list(affected_accounts),
            total_blast_radius=total_blast_radius,
            risk_level=self._calculate_risk_level(
                direct_perms, assumable_roles, chain_info, total_blast_radius
            ),
            reachable_resources=self._extract_reachable_resources(direct_perms),
            reachable_roles=reachable_roles,
            permission_breakdown=permission_breakdown,
            created_at=datetime.utcnow(),
        )

        # Store analysis
        self.analyses.append(analysis)

        return self._analysis_to_dict(analysis)

    def _get_direct_permissions(
        self, identity_arn: str, scan_id: str | None = None
    ) -> dict:
        """Get direct permissions for an identity from enumerate_iam_results."""
        conn = self._get_connection()
        if not conn:
            return {}

        try:
            cur = conn.cursor()

            query = """
                SELECT id, result_id, scan_id, account_id, principal_arn,
                       principal_name, principal_type, enumeration_method,
                       confirmed_permissions, denied_permissions, error_permissions,
                       permission_count, high_risk_permissions,
                       privesc_capable, data_access_capable, admin_capable
                FROM enumerate_iam_results
                WHERE principal_arn = %s
            """
            params = [identity_arn]

            if scan_id:
                query += " AND scan_id = %s"
                params.append(scan_id)

            query += " ORDER BY created_at DESC LIMIT 1"

            cur.execute(query, params)
            row = cur.fetchone()

            if row:
                return dict(row)
            return {}

        except Exception as e:
            logger.error(f"Error getting direct permissions: {e}")
            return {}
        finally:
            conn.close()

    def _get_assumable_roles(
        self, identity_arn: str, scan_id: str | None = None
    ) -> list[dict]:
        """Get roles that can be assumed by this identity."""
        conn = self._get_connection()
        if not conn:
            return []

        try:
            cur = conn.cursor()

            query = """
                SELECT id, mapping_id, scan_id, cloud_provider, account_id,
                       source_principal_type, source_principal_arn, source_principal_name,
                       source_account_id, target_role_arn, target_role_name,
                       target_account_id, trust_policy, conditions,
                       is_cross_account, is_external_id_required, external_id_value,
                       max_session_duration, assumption_chain_depth, risk_level
                FROM assumed_role_mappings
                WHERE source_principal_arn = %s
            """
            params = [identity_arn]

            if scan_id:
                query += " AND scan_id = %s"
                params.append(scan_id)

            query += " ORDER BY assumption_chain_depth DESC, risk_level ASC"

            cur.execute(query, params)
            rows = cur.fetchall()

            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting assumable roles: {e}")
            return []
        finally:
            conn.close()

    def _calculate_assumption_chain(
        self,
        identity_arn: str,
        visited: set | None = None,
        depth: int = 0,
        max_depth: int = 10,
        scan_id: str | None = None,
    ) -> dict:
        """
        Recursively calculate assumption chain depth and reach.

        Prevents cycles by tracking visited identities.
        """
        if visited is None:
            visited = set()

        # Prevent infinite loops
        if identity_arn in visited or depth >= max_depth:
            return {"max_depth": depth, "total_reach": len(visited), "roles": []}

        visited.add(identity_arn)

        # Get roles this identity can assume
        assumable_roles = self._get_assumable_roles(identity_arn, scan_id)

        current_max_depth = depth
        all_reached_roles = []

        for role in assumable_roles:
            target_arn = role.get("target_role_arn")
            if not target_arn or target_arn in visited:
                continue

            all_reached_roles.append(target_arn)

            # Recursively check what the target role can assume
            sub_chain = self._calculate_assumption_chain(
                target_arn,
                visited=visited.copy(),
                depth=depth + 1,
                max_depth=max_depth,
                scan_id=scan_id,
            )

            current_max_depth = max(current_max_depth, sub_chain.get("max_depth", depth))
            all_reached_roles.extend(sub_chain.get("roles", []))

        return {
            "max_depth": current_max_depth,
            "total_reach": len(visited) + len(all_reached_roles),
            "roles": list(set(all_reached_roles)),
        }

    def _calculate_risk_level(
        self,
        direct_perms: dict,
        assumable_roles: list[dict],
        chain_info: dict,
        total_blast_radius: int,
    ) -> str:
        """Calculate risk level based on thresholds."""
        # Check for critical conditions
        if direct_perms.get("admin_capable", False):
            return "critical"

        cross_account_count = sum(
            1 for r in assumable_roles if r.get("is_cross_account")
        )
        if cross_account_count > 0 and total_blast_radius >= RISK_THRESHOLDS["critical"]["resources"]:
            return "critical"

        # Check for high conditions
        if direct_perms.get("privesc_capable", False):
            return "high"

        if total_blast_radius >= RISK_THRESHOLDS["high"]["resources"]:
            return "high"

        if chain_info.get("max_depth", 1) >= 3:
            return "high"

        # Check for medium conditions
        if total_blast_radius >= RISK_THRESHOLDS["medium"]["resources"]:
            return "medium"

        if direct_perms.get("data_access_capable", False):
            return "medium"

        return "low"

    def _calculate_blast_radius_score(
        self,
        direct_perms: dict,
        assumable_roles: list[dict],
        chain_info: dict,
        affected_accounts: set,
    ) -> int:
        """
        Calculate a numerical blast radius score.

        Score components:
        - Direct permissions count * 1
        - High-risk permissions * 5
        - Assumable roles * 10
        - Cross-account roles * 20
        - Assumption chain depth * 15
        - Additional accounts * 25
        - Admin capable: +100
        - Privesc capable: +50
        """
        score = 0

        # Direct permissions
        perm_count = direct_perms.get("permission_count", 0)
        score += perm_count

        # High-risk permissions
        high_risk = direct_perms.get("high_risk_permissions") or []
        if isinstance(high_risk, list):
            score += len(high_risk) * 5

        # Assumable roles
        score += len(assumable_roles) * 10

        # Cross-account roles
        cross_account = sum(1 for r in assumable_roles if r.get("is_cross_account"))
        score += cross_account * 20

        # Assumption chain depth
        depth = chain_info.get("max_depth", 1)
        if depth > 1:
            score += (depth - 1) * 15

        # Additional accounts
        additional_accounts = len(affected_accounts) - 1
        if additional_accounts > 0:
            score += additional_accounts * 25

        # Capability bonuses
        if direct_perms.get("admin_capable"):
            score += 100

        if direct_perms.get("privesc_capable"):
            score += 50

        if direct_perms.get("data_access_capable"):
            score += 25

        return score

    def _calculate_permission_breakdown(
        self, direct_perms: dict
    ) -> list[PermissionBreakdown]:
        """Calculate breakdown of permissions by service."""
        confirmed = direct_perms.get("confirmed_permissions") or []
        if not isinstance(confirmed, list):
            return []

        # Group permissions by service
        service_perms: dict[str, dict] = {}

        for perm in confirmed:
            if not isinstance(perm, str):
                continue

            parts = perm.split(":")
            if len(parts) < 2:
                continue

            service = parts[0].lower()
            action = perm

            if service not in service_perms:
                service_perms[service] = {
                    "actions": [],
                    "high_risk": [],
                }

            service_perms[service]["actions"].append(action)

            # Check if high-risk
            if action in HIGH_RISK_ACTIONS or f"{service}:*" in HIGH_RISK_ACTIONS:
                service_perms[service]["high_risk"].append(action)

        # Convert to breakdown objects
        breakdowns = []
        for service, data in sorted(service_perms.items(), key=lambda x: -len(x[1]["actions"])):
            breakdowns.append(
                PermissionBreakdown(
                    service=service,
                    action_count=len(data["actions"]),
                    resource_count=len(data["actions"]),  # Approximation
                    high_risk_actions=data["high_risk"],
                )
            )

        return breakdowns

    def _determine_identity_type(self, arn: str) -> str:
        """Determine the type of identity from ARN."""
        if not arn:
            return "unknown"

        arn_lower = arn.lower()

        if ":user/" in arn_lower:
            return "user"
        if ":role/" in arn_lower:
            return "role"
        if ":assumed-role/" in arn_lower:
            return "assumed-role"
        if ":root" in arn_lower:
            return "root"
        if ":federated-user/" in arn_lower:
            return "federated-user"
        if ":group/" in arn_lower:
            return "group"

        return "unknown"

    def _extract_account_from_arn(self, arn: str) -> str | None:
        """Extract AWS account ID from ARN."""
        if not arn:
            return None

        parts = arn.split(":")
        if len(parts) >= 5:
            account_id = parts[4]
            if account_id.isdigit() and len(account_id) == 12:
                return account_id

        return None

    def _count_resources(self, direct_perms: dict) -> int:
        """Count estimated resources accessible based on permissions."""
        # Estimate based on permission count and type
        perm_count = direct_perms.get("permission_count", 0)

        # If we have data access capability, multiply
        if direct_perms.get("data_access_capable"):
            return perm_count * 3

        if direct_perms.get("admin_capable"):
            return perm_count * 5

        return perm_count

    def _extract_reachable_resources(self, direct_perms: dict) -> list[str]:
        """Extract list of reachable resource types from permissions."""
        confirmed = direct_perms.get("confirmed_permissions") or []
        if not isinstance(confirmed, list):
            return []

        # Extract unique services
        services = set()
        for perm in confirmed:
            if isinstance(perm, str) and ":" in perm:
                service = perm.split(":")[0].lower()
                services.add(service)

        # Map to resource types
        resource_types = []
        for service in sorted(services):
            category = SERVICE_CATEGORIES.get(service, "Other")
            resource_types.append(f"{service} ({category})")

        return resource_types[:20]  # Limit to top 20

    def _generate_analysis_id(self, identity_arn: str, scan_id: str | None) -> str:
        """Generate a unique analysis ID."""
        content = f"{identity_arn}:{scan_id or 'none'}:{datetime.utcnow().isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _analysis_to_dict(self, analysis: BlastRadiusAnalysis) -> dict:
        """Convert BlastRadiusAnalysis to dictionary."""
        return {
            "analysis_id": analysis.analysis_id,
            "identity_arn": analysis.identity_arn,
            "identity_type": analysis.identity_type,
            "account_id": analysis.account_id,
            "direct_permission_count": analysis.direct_permission_count,
            "direct_resource_count": analysis.direct_resource_count,
            "assumable_roles_count": analysis.assumable_roles_count,
            "assumption_chain_depth": analysis.assumption_chain_depth,
            "cross_account_roles_count": analysis.cross_account_roles_count,
            "affected_accounts": analysis.affected_accounts,
            "total_blast_radius": analysis.total_blast_radius,
            "risk_level": analysis.risk_level,
            "reachable_resources": analysis.reachable_resources,
            "reachable_roles": [
                {
                    "role_arn": r.role_arn,
                    "role_name": r.role_name,
                    "account_id": r.account_id,
                    "is_cross_account": r.is_cross_account,
                    "assumption_depth": r.assumption_depth,
                }
                for r in analysis.reachable_roles
            ],
            "permission_breakdown": [
                {
                    "service": p.service,
                    "action_count": p.action_count,
                    "resource_count": p.resource_count,
                    "high_risk_actions": p.high_risk_actions,
                }
                for p in analysis.permission_breakdown
            ],
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        }

    def analyze_for_scan(self, scan_id: str) -> list[dict]:
        """Analyze blast radius for all identities in a scan."""
        logger.info(f"Analyzing blast radius for all identities in scan: {scan_id}")

        conn = self._get_connection()
        if not conn:
            return []

        try:
            cur = conn.cursor()

            # Get all unique identities from enumerate_iam_results for this scan
            cur.execute(
                """
                SELECT DISTINCT principal_arn
                FROM enumerate_iam_results
                WHERE scan_id = %s AND principal_arn IS NOT NULL
                """,
                (scan_id,),
            )

            identities = [row["principal_arn"] for row in cur.fetchall()]
            logger.info(f"Found {len(identities)} identities to analyze")

            results = []
            for identity_arn in identities:
                try:
                    analysis = self.analyze_identity(identity_arn, scan_id)
                    results.append(analysis)
                except Exception as e:
                    logger.error(f"Error analyzing identity {identity_arn}: {e}")
                    continue

            return results

        except Exception as e:
            logger.error(f"Error in analyze_for_scan: {e}")
            return []
        finally:
            conn.close()

    def get_summary(self, scan_id: str | None = None) -> dict:
        """Get summary of blast radius analyses."""
        if not self.analyses:
            return {
                "total_identities": 0,
                "by_risk_level": {},
                "by_identity_type": {},
                "cross_account_identities": 0,
                "avg_blast_radius": 0.0,
                "top_risk_identities": [],
            }

        # Filter by scan_id if provided
        analyses = self.analyses
        if scan_id:
            # Would need to store scan_id in analysis - for now use all
            pass

        # Count by risk level
        risk_counts: dict[str, int] = {}
        for analysis in analyses:
            risk = analysis.risk_level
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        # Count by identity type
        type_counts: dict[str, int] = {}
        for analysis in analyses:
            id_type = analysis.identity_type
            type_counts[id_type] = type_counts.get(id_type, 0) + 1

        # Count cross-account
        cross_account = sum(
            1 for a in analyses if a.cross_account_roles_count > 0
        )

        # Calculate average blast radius
        total_radius = sum(a.total_blast_radius for a in analyses)
        avg_radius = total_radius / len(analyses) if analyses else 0.0

        # Get top risk identities
        sorted_analyses = sorted(
            analyses,
            key=lambda a: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.risk_level, 4),
                -a.total_blast_radius,
            ),
        )

        top_risk = [
            self._analysis_to_dict(a)
            for a in sorted_analyses[:10]
        ]

        return {
            "total_identities": len(analyses),
            "by_risk_level": risk_counts,
            "by_identity_type": type_counts,
            "cross_account_identities": cross_account,
            "avg_blast_radius": round(avg_radius, 1),
            "top_risk_identities": top_risk,
        }


def main():
    """Main entry point for blast radius analysis."""
    import sys

    analyzer = BlastRadiusAnalyzer()

    # Check for scan_id argument
    scan_id = sys.argv[1] if len(sys.argv) > 1 else None

    if scan_id:
        print(f"Analyzing blast radius for scan: {scan_id}")
        results = analyzer.analyze_for_scan(scan_id)
    else:
        # Demo with all identities from most recent scan
        conn = analyzer._get_connection()
        if conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT DISTINCT principal_arn
                FROM enumerate_iam_results
                WHERE principal_arn IS NOT NULL
                ORDER BY created_at DESC
                LIMIT 10
                """
            )
            identities = [row["principal_arn"] for row in cur.fetchall()]
            conn.close()

            results = []
            for identity in identities:
                result = analyzer.analyze_identity(identity)
                results.append(result)
        else:
            results = []

    # Print summary
    summary = analyzer.get_summary()
    print(f"\n{'='*60}")
    print("BLAST RADIUS ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total identities analyzed: {summary['total_identities']}")
    print(f"Cross-account identities: {summary['cross_account_identities']}")
    print(f"Average blast radius: {summary['avg_blast_radius']}")

    if summary.get("by_risk_level"):
        print("\nBy Risk Level:")
        for risk, count in sorted(
            summary["by_risk_level"].items(),
            key=lambda x: ["critical", "high", "medium", "low"].index(x[0])
            if x[0] in ["critical", "high", "medium", "low"]
            else 99,
        ):
            print(f"  {risk}: {count}")

    if summary.get("by_identity_type"):
        print("\nBy Identity Type:")
        for id_type, count in sorted(summary["by_identity_type"].items(), key=lambda x: -x[1]):
            print(f"  {id_type}: {count}")

    if summary.get("top_risk_identities"):
        print("\nTop Risk Identities:")
        for identity in summary["top_risk_identities"][:5]:
            print(
                f"  - {identity['identity_arn'][:60]}... "
                f"[{identity['risk_level']}] "
                f"blast_radius={identity['total_blast_radius']}"
            )

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
