"""
Neo4j Synchronization Service

This service handles bidirectional synchronization between PostgreSQL assets table
and Neo4j graph database. Cartography populates Neo4j with cloud asset data, and
this service ensures PostgreSQL stays in sync with Neo4j.

Sync Strategy:
1. Pull assets from Neo4j (populated by Cartography)
2. Reconcile with PostgreSQL assets table
3. Propagate finding counts from PostgreSQL to Neo4j nodes
4. Report discrepancies and sync status
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from neo4j import Driver, GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import get_settings
from models.database import Asset, Finding

logger = logging.getLogger(__name__)


class SyncDirection(str, Enum):
    """Direction of sync operation."""

    NEO4J_TO_PG = "neo4j_to_pg"
    PG_TO_NEO4J = "pg_to_neo4j"
    BIDIRECTIONAL = "bidirectional"


@dataclass
class SyncResult:
    """Result of a sync operation."""

    success: bool
    direction: SyncDirection
    assets_synced: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    assets_deleted: int = 0
    findings_propagated: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SyncStatus:
    """Current sync status between databases."""

    neo4j_connected: bool
    postgres_connected: bool
    neo4j_asset_count: int = 0
    postgres_asset_count: int = 0
    count_mismatch: int = 0
    missing_in_postgres: int = 0
    missing_in_neo4j: int = 0
    last_sync: datetime | None = None
    last_sync_success: bool = True
    details: dict[str, Any] = field(default_factory=dict)


class Neo4jConnection:
    """Manages Neo4j connection with proper resource handling."""

    def __init__(self, uri: str, user: str, password: str):
        self.uri = uri
        self.user = user
        self.password = password
        self._driver: Driver | None = None

    def connect(self) -> Driver:
        """Establish connection to Neo4j."""
        if self._driver is None:
            try:
                self._driver = GraphDatabase.driver(
                    self.uri,
                    auth=(self.user, self.password),
                    max_connection_lifetime=300,
                    max_connection_pool_size=10,
                )
                # Verify connectivity
                self._driver.verify_connectivity()
                logger.info(f"Connected to Neo4j at {self.uri}")
            except AuthError as e:
                logger.error(f"Neo4j authentication failed: {e}")
                raise
            except ServiceUnavailable as e:
                logger.error(f"Neo4j service unavailable: {e}")
                raise
        return self._driver

    def close(self):
        """Close Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")

    def is_connected(self) -> bool:
        """Check if connection is active."""
        if self._driver is None:
            return False
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class Neo4jSyncService:
    """
    Service for synchronizing assets between PostgreSQL and Neo4j.

    Cartography populates Neo4j with cloud assets discovered from AWS, GCP, Azure.
    This service ensures:
    1. PostgreSQL assets table reflects Neo4j data
    2. Finding counts are propagated back to Neo4j nodes
    3. Discrepancies are detected and reported
    """

    # Mapping of Cartography node labels to our asset types
    CARTOGRAPHY_LABEL_MAP = {
        # AWS
        "AWSAccount": "aws:account",
        "EC2Instance": "aws:ec2:instance",
        "S3Bucket": "aws:s3:bucket",
        "RDSInstance": "aws:rds:instance",
        "IAMUser": "aws:iam:user",
        "IAMRole": "aws:iam:role",
        "IAMPolicy": "aws:iam:policy",
        "IAMGroup": "aws:iam:group",
        "SecurityGroup": "aws:ec2:security-group",
        "ELB": "aws:elb",
        "ELBv2": "aws:elbv2",
        "Lambda": "aws:lambda:function",
        "DynamoDBTable": "aws:dynamodb:table",
        "ElasticacheCluster": "aws:elasticache:cluster",
        "RedshiftCluster": "aws:redshift:cluster",
        "EKSCluster": "aws:eks:cluster",
        "ECSCluster": "aws:ecs:cluster",
        "VPC": "aws:ec2:vpc",
        "Subnet": "aws:ec2:subnet",
        "AWSLambdaFunction": "aws:lambda:function",
        "KMSKey": "aws:kms:key",
        "SecretsManagerSecret": "aws:secretsmanager:secret",
        "SNSTopic": "aws:sns:topic",
        "SQSQueue": "aws:sqs:queue",
        # GCP
        "GCPInstance": "gcp:compute:instance",
        "GCPBucket": "gcp:storage:bucket",
        "GCPProject": "gcp:project",
        # Azure
        "AzureVM": "azure:compute:vm",
        "AzureStorageAccount": "azure:storage:account",
        "AzureSubscription": "azure:subscription",
        # Kubernetes
        "KubernetesCluster": "k8s:cluster",
        "KubernetesPod": "k8s:pod",
        "KubernetesNamespace": "k8s:namespace",
    }

    def __init__(self, neo4j_conn: Neo4jConnection):
        self.neo4j = neo4j_conn
        self.settings = get_settings()

    def get_sync_status(self, db: Session) -> SyncStatus:
        """
        Get current synchronization status between PostgreSQL and Neo4j.

        Returns counts from both databases and identifies discrepancies.
        """
        status = SyncStatus(neo4j_connected=False, postgres_connected=False)

        # Check PostgreSQL
        try:
            pg_count = db.query(func.count(Asset.id)).scalar() or 0
            status.postgres_connected = True
            status.postgres_asset_count = pg_count
        except Exception as e:
            logger.error(f"PostgreSQL connection check failed: {e}")
            status.details["postgres_error"] = str(e)

        # Check Neo4j
        try:
            driver = self.neo4j.connect()
            with driver.session() as session:
                # Count all asset nodes (common Cartography labels)
                neo4j_count = 0
                label_counts = {}

                for label in self.CARTOGRAPHY_LABEL_MAP.keys():
                    result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
                    count = result.single()["count"]
                    if count > 0:
                        label_counts[label] = count
                        neo4j_count += count

                status.neo4j_connected = True
                status.neo4j_asset_count = neo4j_count
                status.details["label_counts"] = label_counts

        except Exception as e:
            logger.error(f"Neo4j connection check failed: {e}")
            status.details["neo4j_error"] = str(e)

        # Calculate discrepancies
        status.count_mismatch = abs(status.neo4j_asset_count - status.postgres_asset_count)

        # Get detailed discrepancy info if both connected
        if status.neo4j_connected and status.postgres_connected:
            try:
                discrepancies = self._get_discrepancies(db)
                status.missing_in_postgres = len(discrepancies.get("missing_in_pg", []))
                status.missing_in_neo4j = len(discrepancies.get("missing_in_neo4j", []))
                status.details["discrepancies"] = discrepancies
            except Exception as e:
                logger.warning(f"Could not calculate discrepancies: {e}")

        return status

    def _get_discrepancies(self, db: Session) -> dict[str, list[str]]:
        """Find assets that exist in one database but not the other."""
        discrepancies = {"missing_in_pg": [], "missing_in_neo4j": []}

        # Get all asset IDs from PostgreSQL
        pg_asset_ids = set(row[0] for row in db.query(Asset.asset_id).all())

        # Get all asset IDs from Neo4j
        neo4j_asset_ids = set()
        try:
            driver = self.neo4j.connect()
            with driver.session() as session:
                for label in self.CARTOGRAPHY_LABEL_MAP.keys():
                    result = session.run(
                        f"MATCH (n:{label}) WHERE n.id IS NOT NULL RETURN n.id as id"
                    )
                    for record in result:
                        if record["id"]:
                            neo4j_asset_ids.add(record["id"])
        except Exception as e:
            logger.error(f"Error fetching Neo4j asset IDs: {e}")
            return discrepancies

        # Find discrepancies (limit to first 100 for performance)
        missing_in_pg = list(neo4j_asset_ids - pg_asset_ids)[:100]
        missing_in_neo4j = list(pg_asset_ids - neo4j_asset_ids)[:100]

        discrepancies["missing_in_pg"] = missing_in_pg
        discrepancies["missing_in_neo4j"] = missing_in_neo4j

        return discrepancies

    def sync_from_neo4j(self, db: Session) -> SyncResult:
        """
        Pull assets from Neo4j and sync to PostgreSQL.

        This is the primary sync direction - Cartography populates Neo4j,
        and we sync that data to PostgreSQL for our findings to reference.
        """
        start_time = datetime.utcnow()
        result = SyncResult(success=True, direction=SyncDirection.NEO4J_TO_PG)

        try:
            driver = self.neo4j.connect()
            with driver.session() as session:
                for neo4j_label, asset_type in self.CARTOGRAPHY_LABEL_MAP.items():
                    try:
                        assets = self._fetch_assets_by_label(session, neo4j_label)
                        for asset_data in assets:
                            self._upsert_asset_to_postgres(db, asset_data, asset_type)
                            result.assets_synced += 1
                    except Exception as e:
                        error_msg = f"Error syncing {neo4j_label}: {e}"
                        logger.error(error_msg)
                        result.errors.append(error_msg)

            db.commit()
            logger.info(f"Synced {result.assets_synced} assets from Neo4j to PostgreSQL")

        except Exception as e:
            result.success = False
            result.errors.append(str(e))
            logger.error(f"Neo4j sync failed: {e}")
            db.rollback()

        result.duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        return result

    def _fetch_assets_by_label(self, session, label: str) -> list[dict]:
        """Fetch all assets of a specific label from Neo4j."""
        # Cartography typically stores these properties
        query = f"""
        MATCH (n:{label})
        RETURN n.id as id,
               n.arn as arn,
               n.name as name,
               labels(n) as labels,
               n.region as region,
               n.lastupdated as lastupdated
        """
        result = session.run(query)
        assets = []
        for record in result:
            if record["id"]:
                assets.append(
                    {
                        "id": record["id"],
                        "arn": record.get("arn"),
                        "name": record.get("name"),
                        "labels": record.get("labels", []),
                        "region": record.get("region"),
                        "lastupdated": record.get("lastupdated"),
                    }
                )
        return assets

    def _upsert_asset_to_postgres(self, db: Session, asset_data: dict, asset_type: str):
        """Insert or update asset in PostgreSQL."""
        asset_id = asset_data["id"]

        # Determine cloud provider from asset type
        cloud_provider = "unknown"
        if asset_type.startswith("aws:"):
            cloud_provider = "aws"
        elif asset_type.startswith("gcp:"):
            cloud_provider = "gcp"
        elif asset_type.startswith("azure:"):
            cloud_provider = "azure"
        elif asset_type.startswith("k8s:"):
            cloud_provider = "kubernetes"

        # Extract account ID from ARN if available
        account_id = None
        if asset_data.get("arn"):
            arn_parts = asset_data["arn"].split(":")
            if len(arn_parts) >= 5:
                account_id = arn_parts[4]

        existing = db.query(Asset).filter(Asset.asset_id == asset_id).first()

        if existing:
            # Update existing asset
            existing.asset_name = asset_data.get("name") or existing.asset_name
            existing.region = asset_data.get("region") or existing.region
            existing.is_active = True
            existing.updated_at = datetime.utcnow()
        else:
            # Create new asset
            new_asset = Asset(
                asset_id=asset_id,
                cloud_provider=cloud_provider,
                account_id=account_id,
                region=asset_data.get("region"),
                asset_type=asset_type,
                asset_name=asset_data.get("name"),
                is_active=True,
                metadata={"neo4j_labels": asset_data.get("labels", [])},
            )
            db.add(new_asset)

    def propagate_findings_to_neo4j(self, db: Session) -> SyncResult:
        """
        Propagate finding counts and severity information from PostgreSQL to Neo4j.

        Updates Neo4j nodes with:
        - security_findings_count: Total findings for the asset
        - critical_findings: Count of critical severity findings
        - high_findings: Count of high severity findings
        - last_scan_date: When the asset was last scanned
        """
        start_time = datetime.utcnow()
        result = SyncResult(success=True, direction=SyncDirection.PG_TO_NEO4J)

        try:
            # Get finding counts per resource from PostgreSQL
            finding_stats = (
                db.query(
                    Finding.resource_id,
                    func.count(Finding.id).label("total"),
                    func.count(Finding.id).filter(Finding.severity == "critical").label("critical"),
                    func.count(Finding.id).filter(Finding.severity == "high").label("high"),
                    func.count(Finding.id).filter(Finding.severity == "medium").label("medium"),
                    func.count(Finding.id).filter(Finding.severity == "low").label("low"),
                    func.max(Finding.scan_date).label("last_scan"),
                )
                .filter(Finding.status.in_(["open", "fail"]), Finding.resource_id.isnot(None))
                .group_by(Finding.resource_id)
                .all()
            )

            driver = self.neo4j.connect()
            with driver.session() as session:
                for stats in finding_stats:
                    try:
                        # Update any node with matching id
                        query = """
                        MATCH (n)
                        WHERE n.id = $resource_id OR n.arn = $resource_id
                        SET n.security_findings_count = $total,
                            n.critical_findings = $critical,
                            n.high_findings = $high,
                            n.medium_findings = $medium,
                            n.low_findings = $low,
                            n.last_security_scan = $last_scan
                        RETURN count(n) as updated
                        """
                        update_result = session.run(
                            query,
                            resource_id=stats.resource_id,
                            total=stats.total,
                            critical=stats.critical,
                            high=stats.high,
                            medium=stats.medium,
                            low=stats.low,
                            last_scan=stats.last_scan.isoformat() if stats.last_scan else None,
                        )
                        if update_result.single()["updated"] > 0:
                            result.findings_propagated += 1
                    except Exception as e:
                        result.warnings.append(f"Could not update {stats.resource_id}: {e}")

            logger.info(f"Propagated findings to {result.findings_propagated} Neo4j nodes")

        except Exception as e:
            result.success = False
            result.errors.append(str(e))
            logger.error(f"Finding propagation failed: {e}")

        result.duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        return result

    def full_sync(self, db: Session) -> SyncResult:
        """
        Perform full bidirectional synchronization.

        1. Pull assets from Neo4j to PostgreSQL
        2. Propagate finding counts back to Neo4j
        3. Mark stale assets as inactive
        """
        start_time = datetime.utcnow()
        result = SyncResult(success=True, direction=SyncDirection.BIDIRECTIONAL)

        # Step 1: Sync from Neo4j to PostgreSQL
        neo4j_result = self.sync_from_neo4j(db)
        result.assets_synced = neo4j_result.assets_synced
        result.assets_created = neo4j_result.assets_created
        result.assets_updated = neo4j_result.assets_updated
        result.errors.extend(neo4j_result.errors)
        result.warnings.extend(neo4j_result.warnings)

        if not neo4j_result.success:
            result.success = False
            return result

        # Step 2: Propagate findings to Neo4j
        propagate_result = self.propagate_findings_to_neo4j(db)
        result.findings_propagated = propagate_result.findings_propagated
        result.errors.extend(propagate_result.errors)
        result.warnings.extend(propagate_result.warnings)

        if not propagate_result.success:
            result.success = False

        result.duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        return result

    def mark_stale_assets(self, db: Session, hours: int = 24) -> int:
        """
        Mark assets as inactive if they haven't been seen in Neo4j recently.

        Returns count of assets marked as stale.
        """
        cutoff = datetime.utcnow()
        stale_count = 0

        try:
            # Get current Neo4j asset IDs
            neo4j_ids = set()
            driver = self.neo4j.connect()
            with driver.session() as session:
                for label in self.CARTOGRAPHY_LABEL_MAP.keys():
                    result = session.run(
                        f"MATCH (n:{label}) WHERE n.id IS NOT NULL RETURN n.id as id"
                    )
                    for record in result:
                        if record["id"]:
                            neo4j_ids.add(record["id"])

            # Mark assets not in Neo4j as inactive
            stale_assets = (
                db.query(Asset)
                .filter(Asset.asset_id.notin_(neo4j_ids), Asset.is_active == True)
                .all()
            )

            for asset in stale_assets:
                asset.is_active = False
                asset.updated_at = cutoff
                stale_count += 1

            db.commit()
            logger.info(f"Marked {stale_count} stale assets as inactive")

        except Exception as e:
            logger.error(f"Error marking stale assets: {e}")
            db.rollback()

        return stale_count


def get_neo4j_sync_service() -> Neo4jSyncService:
    """Factory function to create Neo4jSyncService with configured connection."""
    settings = get_settings()
    conn = Neo4jConnection(
        uri=settings.neo4j_uri, user=settings.neo4j_user, password=settings.neo4j_password
    )
    return Neo4jSyncService(conn)
