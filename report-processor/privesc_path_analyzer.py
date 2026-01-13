#!/usr/bin/env python3
"""
Privilege Escalation Path Analyzer

Discovers IAM privilege escalation paths by:
1. Loading security findings related to IAM permissions from database
2. Matching findings against known escalation techniques (via privesc_path_edges.py)
3. Identifying source principals and potential escalation targets
4. Building escalation paths with graph representation
5. Scoring paths by risk, exploitability, and impact
6. Saving discovered paths to database
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field

import psycopg2
from psycopg2.extras import Json

from privesc_path_edges import (
    ESCALATION_METHODS,
    SOURCE_PRINCIPAL_TYPES,
    TARGET_PRINCIPAL_TYPES,
    find_matching_escalation_methods,
    generate_poc_command,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class PrivescPathNode:
    """Represents a node in the privilege escalation path."""

    node_id: str
    node_type: str  # 'source', 'intermediate', 'target'
    principal_type: str
    principal_arn: str | None
    principal_name: str
    account_id: str | None = None
    permissions: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class PrivescPathEdge:
    """Represents an edge (escalation step) in the path."""

    edge_id: str
    source_node: str
    target_node: str
    escalation_method: str
    required_permissions: list[str]
    finding_id: int | None = None
    exploitability: str = "theoretical"
    poc_command: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class PrivescPath:
    """Represents a discovered privilege escalation path."""

    path_id: str
    cloud_provider: str
    account_id: str | None
    source_principal_type: str
    source_principal_arn: str | None
    source_principal_name: str
    target_principal_type: str
    target_principal_arn: str | None
    target_principal_name: str
    escalation_method: str
    escalation_details: dict
    path_nodes: list[dict]
    path_edges: list[dict]
    risk_score: int
    exploitability: str
    requires_conditions: list[str]
    mitre_techniques: list[str]
    poc_commands: list[dict]
    finding_ids: list[int]


class PrivescPathAnalyzer:
    """Main privilege escalation path analysis engine."""

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

        # Tracking
        self.findings: list[dict] = []
        self.discovered_paths: list[PrivescPath] = []
        self.principal_cache: dict[str, dict] = {}

    def connect_db(self):
        """Connect to PostgreSQL database."""
        try:
            return psycopg2.connect(**self.db_config)
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return None

    def load_findings(self, scan_id: str | None = None) -> list[dict]:
        """Load IAM-related findings from database."""
        conn = self.connect_db()
        if not conn:
            return []

        try:
            cur = conn.cursor()

            # Query findings related to IAM, privilege escalation, and access control
            query = """
                SELECT id, finding_id, tool, cloud_provider, account_id, region,
                       resource_type, resource_id, resource_name, severity, status,
                       title, description, metadata
                FROM findings
                WHERE status IN ('open', 'fail')
                AND cloud_provider = 'aws'
                AND (
                    resource_type ILIKE '%iam%'
                    OR resource_type ILIKE '%role%'
                    OR resource_type ILIKE '%user%'
                    OR resource_type ILIKE '%policy%'
                    OR resource_type ILIKE '%group%'
                    OR title ILIKE '%iam%'
                    OR title ILIKE '%privilege%'
                    OR title ILIKE '%permission%'
                    OR title ILIKE '%policy%'
                    OR title ILIKE '%role%'
                    OR title ILIKE '%assume%'
                    OR title ILIKE '%access%key%'
                    OR title ILIKE '%passrole%'
                    OR finding_id ILIKE '%iam%'
                    OR finding_id ILIKE '%privilege%'
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

            logger.info(f"Loaded {len(findings)} IAM-related findings from database")
            self.findings = findings
            return findings

        except Exception as e:
            logger.error(f"Error loading findings: {e}")
            return []
        finally:
            conn.close()

    def analyze_findings(self) -> list[PrivescPath]:
        """Analyze findings and discover privilege escalation paths."""
        logger.info("Analyzing findings for privilege escalation paths...")

        self.discovered_paths = []
        processed_methods = set()

        for finding in self.findings:
            # Find matching escalation methods for this finding
            matches = find_matching_escalation_methods(finding)

            for match in matches:
                method_id = match["method_id"]
                method_def = match["method_def"]

                # Create unique key to avoid duplicates
                path_key = f"{finding.get('account_id')}:{method_id}:{finding.get('resource_id')}"
                if path_key in processed_methods:
                    continue
                processed_methods.add(path_key)

                # Build privilege escalation path
                path = self._build_escalation_path(finding, method_id, method_def)
                if path:
                    self.discovered_paths.append(path)

        # Sort by risk score
        self.discovered_paths.sort(key=lambda p: p.risk_score, reverse=True)

        logger.info(f"Discovered {len(self.discovered_paths)} privilege escalation paths")
        return self.discovered_paths

    def _build_escalation_path(
        self, finding: dict, method_id: str, method_def: dict
    ) -> PrivescPath | None:
        """Build a privilege escalation path from a finding and method."""
        try:
            # Extract source principal info from finding
            source_info = self._extract_principal_info(finding)

            # Determine target based on escalation method
            target_type = method_def.get("escalation_to", "admin_role")
            target_info = self._get_target_info(target_type, finding)

            # Build path nodes
            source_node = PrivescPathNode(
                node_id=f"source_{source_info['arn'] or source_info['name']}",
                node_type="source",
                principal_type=source_info["type"],
                principal_arn=source_info["arn"],
                principal_name=source_info["name"],
                account_id=finding.get("account_id"),
                permissions=method_def.get("required_permissions", []),
            )

            target_node = PrivescPathNode(
                node_id=f"target_{target_type}",
                node_type="target",
                principal_type=target_type,
                principal_arn=target_info.get("arn"),
                principal_name=target_info.get("name", TARGET_PRINCIPAL_TYPES.get(target_type, target_type)),
                account_id=finding.get("account_id"),
            )

            # Build path edge
            context = {
                "user_name": source_info["name"],
                "role_name": source_info["name"],
                "role_arn": source_info["arn"],
                "policy_arn": finding.get("resource_id"),
                "target_user": target_info.get("name", "admin-user"),
                "attacker_arn": source_info["arn"],
                "group_name": source_info["name"],
                "account_id": finding.get("account_id"),
            }

            poc_command = generate_poc_command(method_id, context)

            edge = PrivescPathEdge(
                edge_id=f"edge_{method_id}_{finding.get('id')}",
                source_node=source_node.node_id,
                target_node=target_node.node_id,
                escalation_method=method_id,
                required_permissions=method_def.get("required_permissions", []),
                finding_id=finding.get("id"),
                exploitability=method_def.get("exploitability", "theoretical"),
                poc_command=poc_command,
            )

            # Calculate risk score
            risk_score = self._calculate_risk_score(finding, method_def)

            # Generate unique path ID
            path_content = f"{source_info['arn']}:{method_id}:{target_type}"
            path_id = hashlib.md5(path_content.encode()).hexdigest()[:16]

            # Build PoC commands list
            poc_commands = []
            if poc_command:
                poc_commands.append({
                    "name": method_def["name"],
                    "description": method_def.get("description", ""),
                    "command": poc_command,
                })

            # Serialize nodes and edges
            nodes_json = [
                {
                    "id": source_node.node_id,
                    "type": source_node.node_type,
                    "principal_type": source_node.principal_type,
                    "principal_arn": source_node.principal_arn,
                    "principal_name": source_node.principal_name,
                    "permissions": source_node.permissions,
                },
                {
                    "id": target_node.node_id,
                    "type": target_node.node_type,
                    "principal_type": target_node.principal_type,
                    "principal_arn": target_node.principal_arn,
                    "principal_name": target_node.principal_name,
                },
            ]

            edges_json = [
                {
                    "id": edge.edge_id,
                    "source": edge.source_node,
                    "target": edge.target_node,
                    "method": edge.escalation_method,
                    "permissions": edge.required_permissions,
                    "exploitability": edge.exploitability,
                }
            ]

            # Escalation details
            escalation_details = {
                "method_category": method_def.get("category", "unknown"),
                "required_permissions": method_def.get("required_permissions", []),
                "impact": method_def.get("impact", "medium"),
                "description": method_def.get("description", ""),
            }

            return PrivescPath(
                path_id=path_id,
                cloud_provider="aws",
                account_id=finding.get("account_id"),
                source_principal_type=source_info["type"],
                source_principal_arn=source_info["arn"],
                source_principal_name=source_info["name"],
                target_principal_type=target_type,
                target_principal_arn=target_info.get("arn"),
                target_principal_name=target_info.get("name", TARGET_PRINCIPAL_TYPES.get(target_type, target_type)),
                escalation_method=method_def["name"],
                escalation_details=escalation_details,
                path_nodes=nodes_json,
                path_edges=edges_json,
                risk_score=risk_score,
                exploitability=method_def.get("exploitability", "theoretical"),
                requires_conditions=method_def.get("requires_conditions", []),
                mitre_techniques=method_def.get("mitre_techniques", []),
                poc_commands=poc_commands,
                finding_ids=[finding.get("id")] if finding.get("id") else [],
            )

        except Exception as e:
            logger.error(f"Error building escalation path: {e}")
            return None

    def _extract_principal_info(self, finding: dict) -> dict:
        """Extract principal information from a finding."""
        resource_type = (finding.get("resource_type") or "").lower()
        resource_id = finding.get("resource_id") or ""
        resource_name = finding.get("resource_name") or resource_id

        # Try to determine principal type from resource
        principal_type = "user"
        if "role" in resource_type:
            principal_type = "role"
        elif "group" in resource_type:
            principal_type = "group"
        elif "lambda" in resource_type:
            principal_type = "lambda"
        elif "ec2" in resource_type or "instance" in resource_type:
            principal_type = "ec2"

        # Extract ARN if available
        arn = None
        if resource_id and resource_id.startswith("arn:"):
            arn = resource_id
        elif finding.get("metadata"):
            metadata = finding["metadata"]
            if isinstance(metadata, dict):
                arn = metadata.get("arn") or metadata.get("resource_arn")

        return {
            "type": principal_type,
            "arn": arn,
            "name": resource_name,
        }

    def _get_target_info(self, target_type: str, finding: dict) -> dict:
        """Get target principal information based on escalation target type."""
        account_id = finding.get("account_id") or "ACCOUNT_ID"

        # Generate placeholder ARN based on target type
        arn_templates = {
            "admin_user": f"arn:aws:iam::{account_id}:user/admin",
            "admin_role": f"arn:aws:iam::{account_id}:role/AdminRole",
            "root": f"arn:aws:iam::{account_id}:root",
            "service_role": f"arn:aws:iam::{account_id}:role/ServiceRole",
            "cross_account_role": "arn:aws:iam::TARGET_ACCOUNT:role/CrossAccountRole",
        }

        return {
            "type": target_type,
            "arn": arn_templates.get(target_type),
            "name": TARGET_PRINCIPAL_TYPES.get(target_type, target_type),
        }

    def _calculate_risk_score(self, finding: dict, method_def: dict) -> int:
        """
        Calculate risk score for a privilege escalation path.

        Based on:
        - Base risk of the escalation method
        - Severity of the original finding
        - Exploitability rating
        - Impact level
        - Required conditions/prerequisites
        """
        # Start with method base risk
        base_risk = method_def.get("risk_base", 50)

        # Adjust based on finding severity
        severity = (finding.get("severity") or "").lower()
        severity_multipliers = {
            "critical": 1.2,
            "high": 1.1,
            "medium": 1.0,
            "low": 0.8,
            "informational": 0.6,
        }
        severity_mult = severity_multipliers.get(severity, 1.0)

        # Adjust based on exploitability
        exploitability = method_def.get("exploitability", "theoretical")
        exploit_multipliers = {
            "confirmed": 1.15,
            "likely": 1.0,
            "theoretical": 0.85,
        }
        exploit_mult = exploit_multipliers.get(exploitability, 1.0)

        # Adjust based on impact
        impact = method_def.get("impact", "medium")
        impact_multipliers = {
            "critical": 1.2,
            "high": 1.1,
            "medium": 1.0,
            "low": 0.9,
        }
        impact_mult = impact_multipliers.get(impact, 1.0)

        # Reduce score if conditions are required
        conditions = method_def.get("requires_conditions", [])
        condition_penalty = len(conditions) * 5

        # Calculate final score
        final_score = (base_risk * severity_mult * exploit_mult * impact_mult) - condition_penalty

        # Clamp to 0-100
        return max(0, min(100, int(final_score)))

    def save_paths(self, scan_id: str | None = None) -> int:
        """Save discovered privilege escalation paths to database."""
        conn = self.connect_db()
        if not conn:
            return 0

        saved_count = 0
        try:
            cur = conn.cursor()

            for path in self.discovered_paths:
                try:
                    cur.execute(
                        """
                        INSERT INTO privesc_paths (
                            path_id, scan_id, cloud_provider, account_id,
                            source_principal_type, source_principal_arn, source_principal_name,
                            target_principal_type, target_principal_arn, target_principal_name,
                            escalation_method, escalation_details,
                            path_nodes, path_edges,
                            risk_score, exploitability, requires_conditions,
                            mitre_techniques, poc_commands, finding_ids, status
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        ON CONFLICT (path_id) DO UPDATE SET
                            scan_id = EXCLUDED.scan_id,
                            risk_score = EXCLUDED.risk_score,
                            exploitability = EXCLUDED.exploitability,
                            poc_commands = EXCLUDED.poc_commands,
                            updated_at = NOW()
                        """,
                        (
                            path.path_id,
                            scan_id,
                            path.cloud_provider,
                            path.account_id,
                            path.source_principal_type,
                            path.source_principal_arn,
                            path.source_principal_name,
                            path.target_principal_type,
                            path.target_principal_arn,
                            path.target_principal_name,
                            path.escalation_method,
                            Json(path.escalation_details),
                            Json(path.path_nodes),
                            Json(path.path_edges),
                            path.risk_score,
                            path.exploitability,
                            Json(path.requires_conditions),
                            Json(path.mitre_techniques),
                            Json(path.poc_commands),
                            Json(path.finding_ids),
                            "open",
                        ),
                    )
                    saved_count += 1
                except Exception as e:
                    logger.error(f"Error saving path {path.path_id}: {e}")
                    continue

            conn.commit()
            logger.info(f"Saved {saved_count} privilege escalation paths to database")

        except Exception as e:
            logger.error(f"Error saving paths: {e}")
            conn.rollback()
        finally:
            conn.close()

        return saved_count

    def analyze(self, scan_id: str | None = None) -> list[PrivescPath]:
        """Run full privilege escalation path analysis."""
        logger.info("Starting privilege escalation path analysis...")

        # Load findings
        self.load_findings(scan_id)
        if not self.findings:
            logger.warning("No IAM-related findings to analyze")
            return []

        # Analyze findings for escalation paths
        self.analyze_findings()

        # Save to database
        self.save_paths(scan_id)

        logger.info(f"Privilege escalation analysis complete. Found {len(self.discovered_paths)} paths")
        return self.discovered_paths

    def get_summary(self) -> dict:
        """Get summary statistics of discovered paths."""
        if not self.discovered_paths:
            return {
                "total_paths": 0,
                "critical_paths": 0,
                "high_risk_paths": 0,
                "by_method": {},
                "by_target": {},
            }

        critical_paths = [p for p in self.discovered_paths if p.risk_score >= 80]
        high_risk_paths = [p for p in self.discovered_paths if 60 <= p.risk_score < 80]

        # Count by escalation method
        method_counts: dict[str, int] = {}
        for path in self.discovered_paths:
            method = path.escalation_method
            method_counts[method] = method_counts.get(method, 0) + 1

        # Count by target type
        target_counts: dict[str, int] = {}
        for path in self.discovered_paths:
            target = path.target_principal_type
            target_counts[target] = target_counts.get(target, 0) + 1

        return {
            "total_paths": len(self.discovered_paths),
            "critical_paths": len(critical_paths),
            "high_risk_paths": len(high_risk_paths),
            "by_method": method_counts,
            "by_target": target_counts,
            "top_paths": [
                {
                    "path_id": p.path_id,
                    "method": p.escalation_method,
                    "source": p.source_principal_name,
                    "target": p.target_principal_type,
                    "risk_score": p.risk_score,
                    "exploitability": p.exploitability,
                }
                for p in self.discovered_paths[:5]
            ],
        }


def main():
    """Main entry point for privilege escalation path analysis."""
    analyzer = PrivescPathAnalyzer()

    # Run analysis
    paths = analyzer.analyze()

    # Print summary
    summary = analyzer.get_summary()
    print(f"\n{'='*60}")
    print("PRIVILEGE ESCALATION PATH ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total escalation paths discovered: {summary['total_paths']}")
    print(f"Critical risk paths (80+): {summary['critical_paths']}")
    print(f"High risk paths (60-79): {summary['high_risk_paths']}")

    if summary.get("by_method"):
        print("\nBy Escalation Method:")
        for method, count in sorted(summary["by_method"].items(), key=lambda x: -x[1]):
            print(f"  {method}: {count}")

    if summary.get("by_target"):
        print("\nBy Target Type:")
        for target, count in sorted(summary["by_target"].items(), key=lambda x: -x[1]):
            print(f"  {target}: {count}")

    if summary.get("top_paths"):
        print("\nTop 5 Escalation Paths:")
        for i, p in enumerate(summary["top_paths"], 1):
            print(
                f"  {i}. {p['source']} -> {p['target']} via {p['method']} "
                f"(Risk: {p['risk_score']}, {p['exploitability']})"
            )

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
