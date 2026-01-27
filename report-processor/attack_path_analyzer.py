#!/usr/bin/env python3
"""
Attack Path Analyzer

Discovers attack paths by:
1. Loading security findings from database
2. Mapping findings to graph edges (via attack_path_edges.py)
3. Building an attack graph
4. Finding paths from entry points to targets using BFS
5. Scoring paths by risk and exploitability
6. Saving discovered paths to database
"""

import hashlib
import logging
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field

import psycopg2

# Import edge definitions
from attack_path_edges import (
    ENTRY_POINT_TYPES,
    TARGET_TYPES,
    find_matching_edges,
    generate_poc_command,
)
from psycopg2.extras import Json

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the attack graph."""

    node_id: str
    node_type: str  # 'entry_point', 'resource', 'target'
    name: str
    resource_id: str | None = None
    region: str | None = None
    account_id: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents an edge in the attack graph."""

    edge_id: str
    source_node: str
    target_node: str
    edge_type: str
    finding_id: int | None = None
    name: str = ""
    description: str = ""
    exploitability: str = "theoretical"
    impact: str = "medium"
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    requires_auth: bool = False
    poc_command: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackPath:
    """Represents a discovered attack path."""

    path_id: str
    name: str
    description: str
    entry_point_type: str
    entry_point_id: str | None
    entry_point_name: str
    target_type: str
    target_description: str
    nodes: list[dict]
    edges: list[dict]
    finding_ids: list[int]
    risk_score: int
    exploitability: str
    impact: str
    hop_count: int
    requires_authentication: bool
    requires_privileges: bool
    poc_available: bool
    poc_steps: list[dict]
    mitre_tactics: list[str]
    aws_services: list[str]
    # Confidence scoring fields
    confidence_score: int = 0
    confidence_factors: dict = field(default_factory=dict)


class AttackPathAnalyzer:
    """Main attack path analysis engine."""

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

        # Graph structures
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.adjacency: dict[str, list[GraphEdge]] = defaultdict(list)

        # Tracking
        self.findings: list[dict] = []
        self.discovered_paths: list[AttackPath] = []

    def connect_db(self) -> psycopg2.extensions.connection | None:
        """Connect to PostgreSQL database.

        Returns:
            PostgreSQL connection object, or None if connection fails.

        Note:
            Connection failures are logged but not raised, allowing
            callers to handle missing connections gracefully.
        """
        try:
            return psycopg2.connect(**self.db_config)
        except psycopg2.OperationalError as e:
            logger.error(f"Database connection failed (operational error): {e}")
            return None
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            return None

    def load_findings(self, scan_id: str | None = None) -> list[dict]:
        """Load findings from database."""
        conn = self.connect_db()
        if not conn:
            return []

        try:
            cur = conn.cursor()

            # Query active findings
            query = """
                SELECT id, finding_id, tool, cloud_provider, account_id, region,
                       resource_type, resource_id, resource_name, severity, status,
                       title, description, metadata
                FROM findings
                WHERE status IN ('open', 'fail')
                AND cloud_provider = 'aws'
            """
            params = []

            if scan_id:
                query += " AND scan_id = %s"
                params.append(scan_id)

            query += " ORDER BY severity DESC"

            cur.execute(query, params)
            columns = [desc[0] for desc in cur.description]
            findings = [dict(zip(columns, row, strict=False)) for row in cur.fetchall()]

            logger.info(f"Loaded {len(findings)} AWS findings from database")
            self.findings = findings
            return findings

        except Exception as e:
            logger.error(f"Error loading findings: {e}")
            return []
        finally:
            conn.close()

    def build_graph(self):
        """Build attack graph from findings using edge definitions."""
        logger.info("Building attack graph from findings...")

        # Reset graph
        self.nodes = {}
        self.edges = []
        self.adjacency = defaultdict(list)

        # Add target nodes (attack goals)
        for target_type, description in TARGET_TYPES.items():
            node_id = f"target_{target_type}"
            self.nodes[node_id] = GraphNode(
                node_id=node_id,
                node_type="target",
                name=description,
                metadata={"target_type": target_type},
            )

        # Process each finding and map to edges
        for finding in self.findings:
            matched_edges = find_matching_edges(finding)

            for match in matched_edges:
                edge_def = match["edge_def"]
                edge_id = match["edge_id"]

                # Create resource node if it doesn't exist
                resource_id = finding.get("resource_id") or finding.get("finding_id")
                resource_node_id = f"resource_{resource_id}"

                if resource_node_id not in self.nodes:
                    self.nodes[resource_node_id] = GraphNode(
                        node_id=resource_node_id,
                        node_type="resource",
                        name=finding.get("resource_name") or finding.get("title"),
                        resource_id=resource_id,
                        region=finding.get("region"),
                        account_id=finding.get("account_id"),
                        metadata={
                            "resource_type": finding.get("resource_type"),
                            "severity": finding.get("severity"),
                            "tool": finding.get("tool"),
                        },
                    )

                # If this is an entry point, create entry node
                entry_point_type = edge_def.get("entry_point_type")
                if entry_point_type:
                    entry_node_id = f"entry_{entry_point_type}_{resource_id}"
                    if entry_node_id not in self.nodes:
                        self.nodes[entry_node_id] = GraphNode(
                            node_id=entry_node_id,
                            node_type="entry_point",
                            name=ENTRY_POINT_TYPES.get(entry_point_type, entry_point_type),
                            resource_id=resource_id,
                            region=finding.get("region"),
                            account_id=finding.get("account_id"),
                            metadata={"entry_point_type": entry_point_type},
                        )

                    # Edge from entry point to resource
                    edge = GraphEdge(
                        edge_id=f"{edge_id}_{finding.get('id')}",
                        source_node=entry_node_id,
                        target_node=resource_node_id,
                        edge_type=edge_id,
                        finding_id=finding.get("id"),
                        name=edge_def["name"],
                        description=edge_def["description"],
                        exploitability=edge_def["exploitability"],
                        impact=edge_def["impact"],
                        mitre_tactics=edge_def.get("mitre_tactics", []),
                        mitre_techniques=edge_def.get("mitre_techniques", []),
                        requires_auth=edge_def.get("requires_auth", False),
                        poc_command=generate_poc_command(match),
                    )
                    self.edges.append(edge)
                    self.adjacency[entry_node_id].append(edge)

                # Create edges to target nodes
                for target_type in edge_def.get("target_types", []):
                    target_node_id = f"target_{target_type}"

                    edge = GraphEdge(
                        edge_id=f"{edge_id}_{finding.get('id')}_to_{target_type}",
                        source_node=resource_node_id,
                        target_node=target_node_id,
                        edge_type=edge_id,
                        finding_id=finding.get("id"),
                        name=edge_def["name"],
                        description=edge_def["description"],
                        exploitability=edge_def["exploitability"],
                        impact=edge_def["impact"],
                        mitre_tactics=edge_def.get("mitre_tactics", []),
                        mitre_techniques=edge_def.get("mitre_techniques", []),
                        requires_auth=edge_def.get("requires_auth", False),
                        poc_command=generate_poc_command(match),
                    )
                    self.edges.append(edge)
                    self.adjacency[resource_node_id].append(edge)

        logger.info(f"Built graph with {len(self.nodes)} nodes and {len(self.edges)} edges")

    def find_paths(self, max_depth: int = 5) -> list[AttackPath]:
        """Find attack paths using BFS from entry points to targets."""
        logger.info("Finding attack paths...")

        self.discovered_paths = []

        # Get all entry point nodes
        entry_nodes = [
            node_id for node_id, node in self.nodes.items() if node.node_type == "entry_point"
        ]

        # Get all target nodes
        target_nodes = [
            node_id for node_id, node in self.nodes.items() if node.node_type == "target"
        ]

        logger.info(f"Found {len(entry_nodes)} entry points and {len(target_nodes)} targets")

        # BFS from each entry point
        for entry_node_id in entry_nodes:
            entry_node = self.nodes[entry_node_id]

            # BFS queue: (current_node, path_nodes, path_edges, depth)
            queue = deque([(entry_node_id, [entry_node_id], [], 0)])
            visited_paths: set[str] = set()

            while queue:
                current_node, path_nodes, path_edges, depth = queue.popleft()

                if depth > max_depth:
                    continue

                # Check if we reached a target
                if current_node.startswith("target_"):
                    path_key = "->".join(path_nodes)
                    if path_key not in visited_paths:
                        visited_paths.add(path_key)

                        # Create attack path
                        attack_path = self._create_attack_path(
                            entry_node, self.nodes[current_node], path_nodes, path_edges
                        )
                        if attack_path:
                            self.discovered_paths.append(attack_path)

                    continue

                # Explore neighbors
                for edge in self.adjacency.get(current_node, []):
                    next_node = edge.target_node
                    if next_node not in path_nodes:  # Avoid cycles
                        new_path_nodes = path_nodes + [next_node]
                        new_path_edges = path_edges + [edge]
                        queue.append((next_node, new_path_nodes, new_path_edges, depth + 1))

        logger.info(f"Discovered {len(self.discovered_paths)} attack paths")
        return self.discovered_paths

    def _create_attack_path(
        self,
        entry_node: GraphNode,
        target_node: GraphNode,
        path_nodes: list[str],
        path_edges: list[GraphEdge],
    ) -> AttackPath | None:
        """Create an AttackPath object from a discovered path."""
        if not path_edges:
            return None

        # Calculate path properties
        finding_ids = list(
            set(edge.finding_id for edge in path_edges if edge.finding_id is not None)
        )

        # Determine exploitability (worst case in chain)
        exploitability_order = ["confirmed", "likely", "theoretical"]
        exploitabilities = [edge.exploitability for edge in path_edges]
        best_exploitability = min(
            exploitabilities,
            key=lambda x: exploitability_order.index(x) if x in exploitability_order else 99,
        )

        # Determine impact (worst case)
        impact_order = ["critical", "high", "medium", "low"]
        impacts = [edge.impact for edge in path_edges]
        worst_impact = min(
            impacts, key=lambda x: impact_order.index(x) if x in impact_order else 99
        )

        # Get entry and target types for risk calculation
        entry_type = entry_node.metadata.get("entry_point_type", "unknown")
        target_type = target_node.metadata.get("target_type", "unknown")

        # Authentication requirements
        requires_auth = any(edge.requires_auth for edge in path_edges)
        requires_privileges = any(
            "privilege" in edge.name.lower() or "admin" in edge.name.lower() for edge in path_edges
        )

        # Calculate risk score using CVSS-style methodology (0-100)
        risk_score = self._calculate_risk_score(
            path_edges,
            best_exploitability,
            worst_impact,
            entry_type,
            target_type,
            requires_auth,
            requires_privileges,
        )

        # Collect MITRE tactics and AWS services
        mitre_tactics = list(set(tactic for edge in path_edges for tactic in edge.mitre_tactics))

        aws_services = list(
            set(
                self.nodes[node_id].metadata.get("resource_type", "").split(".")[0]
                for node_id in path_nodes
                if node_id in self.nodes and self.nodes[node_id].node_type == "resource"
            )
        )

        # Generate PoC steps
        poc_steps = self._generate_poc_steps(path_edges)
        poc_available = len(poc_steps) > 0

        # Calculate confidence score
        confidence_score, confidence_factors = self._calculate_confidence_score(
            finding_ids,
            path_edges,
            best_exploitability,
            poc_available,
        )

        # Build name and description
        name = f"{ENTRY_POINT_TYPES.get(entry_type, entry_type)} -> {TARGET_TYPES.get(target_type, target_type)}"
        description = f"Attack path from {entry_node.name} leading to {target_node.name}"

        # Generate unique path ID
        path_content = f"{entry_node.node_id}:{':'.join(path_nodes)}:{target_node.node_id}"
        path_id = hashlib.md5(path_content.encode()).hexdigest()[:16]

        # Serialize nodes and edges for storage
        nodes_json = [
            {
                "id": node_id,
                "type": self.nodes[node_id].node_type if node_id in self.nodes else "unknown",
                "name": self.nodes[node_id].name if node_id in self.nodes else node_id,
                "resource_id": self.nodes[node_id].resource_id if node_id in self.nodes else None,
                "region": self.nodes[node_id].region if node_id in self.nodes else None,
            }
            for node_id in path_nodes
        ]

        edges_json = [
            {
                "id": edge.edge_id,
                "source": edge.source_node,
                "target": edge.target_node,
                "type": edge.edge_type,
                "name": edge.name,
                "finding_id": edge.finding_id,
                "exploitability": edge.exploitability,
                "impact": edge.impact,
            }
            for edge in path_edges
        ]

        return AttackPath(
            path_id=path_id,
            name=name,
            description=description,
            entry_point_type=entry_type,
            entry_point_id=entry_node.resource_id,
            entry_point_name=entry_node.name,
            target_type=target_type,
            target_description=target_node.name,
            nodes=nodes_json,
            edges=edges_json,
            finding_ids=finding_ids,
            risk_score=risk_score,
            exploitability=best_exploitability,
            impact=worst_impact,
            hop_count=len(path_edges),
            requires_authentication=requires_auth,
            requires_privileges=requires_privileges,
            poc_available=poc_available,
            poc_steps=poc_steps,
            mitre_tactics=mitre_tactics,
            aws_services=aws_services,
            confidence_score=confidence_score,
            confidence_factors=confidence_factors,
        )

    def _calculate_risk_score(
        self,
        path_edges: list[GraphEdge],
        exploitability: str,
        impact: str,
        entry_point_type: str,
        target_type: str,
        requires_auth: bool,
        requires_privileges: bool,
    ) -> int:
        """
        Calculate risk score using CVSS-inspired methodology (0-100).

        Based on CVSS 3.1 concepts:
        - Impact Score: What damage can be done (based on target)
        - Exploitability Score: How easy is it to exploit (AV, AC, PR, UI)

        Final Score = (Impact + Exploitability) normalized to 0-100
        """

        # =================================================================
        # IMPACT SCORE (0-10 scale, based on CIA triad impact of target)
        # =================================================================
        target_impact_scores = {
            "account_takeover": 10.0,  # Full C/I/A compromise
            "data_exfiltration": 8.5,  # High confidentiality impact
            "privilege_escalation": 8.0,  # Enables further attacks
            "persistence": 7.0,  # Integrity/availability impact
            "lateral_movement": 6.0,  # Enabler, indirect impact
            "cryptomining": 5.0,  # Resource abuse
            "ransomware": 9.5,  # Full I/A compromise
        }
        impact_score = target_impact_scores.get(target_type, 5.0)

        # =================================================================
        # EXPLOITABILITY SCORE (CVSS-style: 8.22 × AV × AC × PR × UI)
        # =================================================================

        # Attack Vector (AV) - How accessible is the entry point?
        # Network (internet-facing): 0.85
        # Adjacent (requires network proximity): 0.62
        # Local (requires existing access): 0.55
        # Physical: 0.20 (not really applicable for cloud)
        internet_accessible_entries = {
            "public_s3",
            "public_lambda",
            "public_ec2",
            "public_rds",
            "public_security_group",
            "public_api_gateway",
        }
        internal_entries = {"exposed_credentials", "weak_iam_policy"}

        if entry_point_type in internet_accessible_entries:
            attack_vector = 0.85  # Network - remotely exploitable
        elif entry_point_type in internal_entries:
            attack_vector = 0.55  # Local - requires some existing access
        else:
            attack_vector = 0.62  # Adjacent - default

        # Attack Complexity (AC) - How complex is the attack chain?
        # Low: 0.77 (straightforward, 1-2 hops)
        # High: 0.44 (requires multiple conditions, 3+ hops)
        hop_count = len(path_edges)
        if hop_count <= 2:
            attack_complexity = 0.77  # Low complexity
        elif hop_count <= 4:
            attack_complexity = 0.60  # Medium complexity
        else:
            attack_complexity = 0.44  # High complexity

        # Privileges Required (PR) - What access level is needed?
        # None: 0.85
        # Low (basic authentication): 0.62
        # High (admin/elevated privileges): 0.27
        if not requires_auth:
            privileges_required = 0.85  # None - unauthenticated attack
        elif requires_privileges:
            privileges_required = 0.27  # High - needs elevated access
        else:
            privileges_required = 0.62  # Low - basic auth needed

        # User Interaction (UI) - Does it require victim action?
        # For cloud attacks, most don't require user interaction
        # None: 0.85, Required: 0.62
        user_interaction = 0.85  # Assume no user interaction for cloud

        # Exploitability confirmation multiplier
        # Adjusts based on whether the vulnerability is confirmed exploitable
        exploit_confidence = {
            "confirmed": 1.0,  # Known exploitable, tools exist
            "likely": 0.85,  # Documented technique, feasible
            "theoretical": 0.65,  # Possible but unproven
        }
        confidence_mult = exploit_confidence.get(exploitability, 0.75)

        # Calculate exploitability sub-score (CVSS formula: 8.22 × AV × AC × PR × UI)
        exploitability_score = (
            8.22 * attack_vector * attack_complexity * privileges_required * user_interaction
        )

        # Apply confidence multiplier
        exploitability_score *= confidence_mult

        # =================================================================
        # FINAL SCORE CALCULATION
        # =================================================================
        # Combine impact and exploitability, normalize to 0-100
        # CVSS uses: Roundup(Min[(Impact + Exploitability), 10])
        # We'll use: ((Impact + Exploitability) / 2) * 10 for 0-100 scale

        raw_score = impact_score + exploitability_score

        # Normalize: max possible is ~18.22 (10 + 8.22), scale to 100
        normalized_score = (raw_score / 18.22) * 100

        # Apply minimum floor based on target criticality
        # Even a hard-to-exploit path to account takeover should score reasonably
        min_scores = {
            "account_takeover": 35,
            "data_exfiltration": 25,
            "privilege_escalation": 20,
            "ransomware": 30,
        }
        min_score = min_scores.get(target_type, 10)

        final_score = max(min_score, int(normalized_score))

        # Clamp to 0-100
        return max(0, min(100, final_score))

    def _generate_poc_steps(self, path_edges: list[GraphEdge]) -> list[dict]:
        """Generate PoC steps for an attack path."""
        poc_steps = []

        for i, edge in enumerate(path_edges):
            if edge.poc_command:
                step = {
                    "step": i + 1,
                    "name": edge.name,
                    "description": edge.description,
                    "command": edge.poc_command,
                    "mitre_technique": edge.mitre_techniques[0] if edge.mitre_techniques else None,
                    "requires_auth": edge.requires_auth,
                }
                poc_steps.append(step)

        return poc_steps

    def _calculate_confidence_score(
        self,
        finding_ids: list[int],
        path_edges: list[GraphEdge],
        exploitability: str,
        poc_available: bool,
    ) -> tuple[int, dict]:
        """
        Calculate confidence score for an attack path (0-100).

        Confidence factors:
        - Tool agreement (30%): Multiple tools confirm same issue
        - PoC validation (40%): Verified exploitable
        - Evidence count (30%): Amount of supporting data

        Returns:
            tuple: (confidence_score, confidence_factors dict)
        """
        factors = {
            "tool_agreement": {"score": 0, "weight": 30, "details": ""},
            "poc_validation": {"score": 0, "weight": 40, "details": ""},
            "evidence_count": {"score": 0, "weight": 30, "details": ""},
        }

        # =================================================================
        # TOOL AGREEMENT (30%)
        # Multiple tools reporting the same or related issues increases confidence
        # =================================================================
        tools_seen = set()
        for finding in self.findings:
            if finding.get("id") in finding_ids:
                tool = finding.get("tool", "").lower()
                if tool:
                    tools_seen.add(tool)

        num_tools = len(tools_seen)
        if num_tools >= 3:
            factors["tool_agreement"]["score"] = 100
            factors["tool_agreement"]["details"] = f"Confirmed by {num_tools} tools: {', '.join(tools_seen)}"
        elif num_tools == 2:
            factors["tool_agreement"]["score"] = 75
            factors["tool_agreement"]["details"] = f"Confirmed by 2 tools: {', '.join(tools_seen)}"
        elif num_tools == 1:
            factors["tool_agreement"]["score"] = 40
            factors["tool_agreement"]["details"] = f"Single tool detection: {', '.join(tools_seen)}"
        else:
            factors["tool_agreement"]["score"] = 0
            factors["tool_agreement"]["details"] = "No tool confirmation"

        # =================================================================
        # POC VALIDATION (40%)
        # Whether the path has been validated as exploitable
        # =================================================================
        if exploitability == "confirmed":
            factors["poc_validation"]["score"] = 100
            factors["poc_validation"]["details"] = "Confirmed exploitable through validation"
        elif exploitability == "likely" and poc_available:
            factors["poc_validation"]["score"] = 75
            factors["poc_validation"]["details"] = "Likely exploitable, PoC commands available"
        elif exploitability == "likely":
            factors["poc_validation"]["score"] = 60
            factors["poc_validation"]["details"] = "Likely exploitable based on findings"
        elif poc_available:
            factors["poc_validation"]["score"] = 40
            factors["poc_validation"]["details"] = "Theoretical, but PoC commands available"
        else:
            factors["poc_validation"]["score"] = 20
            factors["poc_validation"]["details"] = "Theoretical vulnerability"

        # =================================================================
        # EVIDENCE COUNT (30%)
        # Amount of supporting evidence (findings, edges, nodes)
        # =================================================================
        num_findings = len(finding_ids)
        num_edges = len(path_edges)

        # Also check for additional metadata evidence
        evidence_details = []
        for finding in self.findings:
            if finding.get("id") in finding_ids:
                metadata = finding.get("metadata") or {}
                if metadata.get("evidence"):
                    evidence_details.append("has evidence")
                if metadata.get("resource_tags"):
                    evidence_details.append("has resource tags")

        total_evidence = num_findings + num_edges + len(set(evidence_details))

        if total_evidence >= 10:
            factors["evidence_count"]["score"] = 100
            factors["evidence_count"]["details"] = f"Strong evidence: {num_findings} findings, {num_edges} edges"
        elif total_evidence >= 5:
            factors["evidence_count"]["score"] = 70
            factors["evidence_count"]["details"] = f"Moderate evidence: {num_findings} findings, {num_edges} edges"
        elif total_evidence >= 2:
            factors["evidence_count"]["score"] = 40
            factors["evidence_count"]["details"] = f"Limited evidence: {num_findings} findings, {num_edges} edges"
        else:
            factors["evidence_count"]["score"] = 20
            factors["evidence_count"]["details"] = "Minimal evidence"

        # =================================================================
        # CALCULATE TOTAL SCORE
        # =================================================================
        total_score = 0
        for factor_name, factor_data in factors.items():
            weighted_score = (factor_data["score"] * factor_data["weight"]) / 100
            total_score += weighted_score

        # Round to integer and clamp to 0-100
        confidence_score = max(0, min(100, int(total_score)))

        return confidence_score, factors

    def save_paths(self, scan_id: str | None = None) -> int:
        """Save discovered attack paths to database."""
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
                        INSERT INTO attack_paths (
                            path_id, scan_id, name, description,
                            entry_point_type, entry_point_id, entry_point_name,
                            target_type, target_description,
                            nodes, edges, finding_ids,
                            risk_score, exploitability, impact, hop_count,
                            requires_authentication, requires_privileges,
                            poc_available, poc_steps,
                            mitre_tactics, aws_services,
                            confidence_score, confidence_factors
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        ON CONFLICT (path_id) DO UPDATE SET
                            scan_id = EXCLUDED.scan_id,
                            risk_score = EXCLUDED.risk_score,
                            exploitability = EXCLUDED.exploitability,
                            poc_steps = EXCLUDED.poc_steps,
                            confidence_score = EXCLUDED.confidence_score,
                            confidence_factors = EXCLUDED.confidence_factors,
                            updated_at = NOW()
                    """,
                        (
                            path.path_id,
                            scan_id,
                            path.name,
                            path.description,
                            path.entry_point_type,
                            path.entry_point_id,
                            path.entry_point_name,
                            path.target_type,
                            path.target_description,
                            Json(path.nodes),
                            Json(path.edges),
                            path.finding_ids,  # PostgreSQL integer[] - pass as list
                            path.risk_score,
                            path.exploitability,
                            path.impact,
                            path.hop_count,
                            path.requires_authentication,
                            path.requires_privileges,
                            path.poc_available,
                            Json(path.poc_steps),
                            path.mitre_tactics,  # PostgreSQL text[] - pass as list
                            path.aws_services,  # PostgreSQL text[] - pass as list
                            path.confidence_score,
                            Json(path.confidence_factors),
                        ),
                    )
                    saved_count += 1
                except Exception as e:
                    logger.error(f"Error saving path {path.path_id}: {e}")
                    continue

            conn.commit()
            logger.info(f"Saved {saved_count} attack paths to database")

        except Exception as e:
            logger.error(f"Error saving paths: {e}")
            conn.rollback()
        finally:
            conn.close()

        return saved_count

    def analyze(self, scan_id: str | None = None) -> list[AttackPath]:
        """Run full attack path analysis."""
        logger.info("Starting attack path analysis...")

        # Load findings
        self.load_findings(scan_id)
        if not self.findings:
            logger.warning("No findings to analyze")
            return []

        # Build graph
        self.build_graph()

        # Find paths
        self.find_paths()

        # Sort by risk score
        self.discovered_paths.sort(key=lambda p: p.risk_score, reverse=True)

        # Save to database
        self.save_paths(scan_id)

        logger.info(f"Attack path analysis complete. Found {len(self.discovered_paths)} paths")
        return self.discovered_paths

    def get_summary(self) -> dict:
        """Get summary statistics of discovered paths."""
        if not self.discovered_paths:
            return {
                "total_paths": 0,
                "critical_paths": 0,
                "high_risk_paths": 0,
                "entry_points": [],
                "targets": [],
            }

        critical_paths = [p for p in self.discovered_paths if p.risk_score >= 80]
        high_risk_paths = [p for p in self.discovered_paths if 60 <= p.risk_score < 80]

        entry_points = list(set(p.entry_point_type for p in self.discovered_paths))
        targets = list(set(p.target_type for p in self.discovered_paths))

        return {
            "total_paths": len(self.discovered_paths),
            "critical_paths": len(critical_paths),
            "high_risk_paths": len(high_risk_paths),
            "entry_points": entry_points,
            "targets": targets,
            "top_paths": [
                {
                    "path_id": p.path_id,
                    "name": p.name,
                    "risk_score": p.risk_score,
                    "exploitability": p.exploitability,
                    "hop_count": p.hop_count,
                }
                for p in self.discovered_paths[:5]
            ],
        }


def main():
    """Main entry point for attack path analysis."""
    analyzer = AttackPathAnalyzer()

    # Run analysis
    paths = analyzer.analyze()

    # Print summary
    summary = analyzer.get_summary()
    print(f"\n{'='*60}")
    print("ATTACK PATH ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total attack paths discovered: {summary['total_paths']}")
    print(f"Critical risk paths (80+): {summary['critical_paths']}")
    print(f"High risk paths (60-79): {summary['high_risk_paths']}")
    print(f"Entry point types: {', '.join(summary['entry_points']) or 'None'}")
    print(f"Target types: {', '.join(summary['targets']) or 'None'}")

    if summary.get("top_paths"):
        print("\nTop 5 Attack Paths:")
        for i, p in enumerate(summary["top_paths"], 1):
            print(
                f"  {i}. {p['name']} (Risk: {p['risk_score']}, {p['exploitability']}, {p['hop_count']} hops)"
            )

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
