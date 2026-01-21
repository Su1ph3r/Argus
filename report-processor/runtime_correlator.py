#!/usr/bin/env python3
"""
Runtime Correlator - Links security findings to CloudTrail events.

This module provides the capability to correlate security findings with
actual CloudTrail events, enabling runtime validation of theoretical
vulnerabilities. It can:

1. Fetch CloudTrail events for specific time windows
2. Match events to findings by resource ARN, principal ARN
3. Detect anomalous events (unusual IPs, off-hours activity)
4. Confirm exploitability of findings via runtime evidence
5. Store correlations in the database for analysis

Security Notes:
- Uses subprocess with shell=False for safe command execution
- All AWS CLI commands use read-only operations
- Gracefully degrades if CloudTrail access is unavailable
"""

import hashlib
import json
import logging
import os
import shlex
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg2
from psycopg2.extras import Json, RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Event patterns to correlate with findings
CORRELATION_PATTERNS = {
    "privesc": {
        "events": [
            "CreatePolicyVersion",
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "CreateAccessKey",
            "UpdateAssumeRolePolicy",
            "PassRole",
            "AddUserToGroup",
            "CreateGroup",
            "AttachGroupPolicy",
            "PutGroupPolicy",
            "CreateRole",
            "CreateLoginProfile",
            "UpdateLoginProfile",
        ],
        "source": "iam.amazonaws.com",
    },
    "data_access": {
        "events": [
            "GetObject",
            "PutObject",
            "DeleteObject",
            "ListBucket",
            "GetBucketAcl",
            "PutBucketAcl",
            "PutBucketPolicy",
            "DeleteBucketPolicy",
            "PutObjectAcl",
            "GetBucketPolicy",
        ],
        "source": "s3.amazonaws.com",
    },
    "credential_usage": {
        "events": [
            "GetSessionToken",
            "AssumeRole",
            "GetFederationToken",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
        ],
        "source": "sts.amazonaws.com",
    },
    "resource_modification": {
        "events": [
            "RunInstances",
            "TerminateInstances",
            "ModifyInstanceAttribute",
            "CreateSecurityGroup",
            "AuthorizeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress",
            "CreateKeyPair",
            "ImportKeyPair",
            "ModifyVpcEndpoint",
        ],
        "source": "ec2.amazonaws.com",
    },
    "secrets_access": {
        "events": [
            "GetSecretValue",
            "PutSecretValue",
            "CreateSecret",
            "DeleteSecret",
            "UpdateSecret",
        ],
        "source": "secretsmanager.amazonaws.com",
    },
    "lambda_execution": {
        "events": [
            "Invoke",
            "CreateFunction",
            "UpdateFunctionCode",
            "UpdateFunctionConfiguration",
            "AddPermission",
        ],
        "source": "lambda.amazonaws.com",
    },
}

# Off-hours definition (outside 6 AM - 10 PM local time)
OFF_HOURS_START = 22  # 10 PM
OFF_HOURS_END = 6  # 6 AM

# Known suspicious source IP patterns
SUSPICIOUS_IP_PATTERNS = [
    "tor-exit",  # Tor exit nodes
]


class RuntimeCorrelator:
    """Correlates security findings with CloudTrail events."""

    def __init__(self, db_config: dict | None = None, aws_region: str = "us-east-1"):
        """
        Initialize the Runtime Correlator.

        Args:
            db_config: Database configuration dictionary. If None, reads from environment.
            aws_region: AWS region for CloudTrail queries.
        """
        if db_config is None:
            db_password = os.environ.get("DB_PASSWORD")
            if not db_password:
                db_password = os.environ.get("POSTGRES_PASSWORD", "")

            self.db_config = {
                "host": os.environ.get("DB_HOST", "postgresql"),
                "database": os.environ.get("DB_NAME", "security_audits"),
                "user": os.environ.get("DB_USER", "auditor"),
                "password": db_password,
            }
        else:
            self.db_config = db_config

        self.aws_region = aws_region
        self._cloudtrail_available: bool | None = None

    def _get_connection(self):
        """Get database connection."""
        return psycopg2.connect(**self.db_config, cursor_factory=RealDictCursor)

    def _check_cloudtrail_access(self) -> bool:
        """
        Check if CloudTrail is accessible.

        Returns:
            True if CloudTrail lookup is available, False otherwise.
        """
        if self._cloudtrail_available is not None:
            return self._cloudtrail_available

        # Try to lookup events (safe read-only)
        cmd = [
            "aws",
            "cloudtrail",
            "lookup-events",
            "--max-results",
            "1",
            "--output",
            "json",
            "--region",
            self.aws_region,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
            self._cloudtrail_available = result.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning("CloudTrail access check timed out")
            self._cloudtrail_available = False
        except Exception as e:
            logger.warning(f"CloudTrail access check failed: {e}")
            self._cloudtrail_available = False

        if not self._cloudtrail_available:
            logger.info("CloudTrail not accessible - runtime correlation will be limited")

        return self._cloudtrail_available

    def fetch_cloudtrail_events(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
        event_names: list[str] | None = None,
        resource_arn: str | None = None,
    ) -> list[dict]:
        """
        Fetch CloudTrail events for correlation.

        Args:
            start_time: Start of time window to query.
            end_time: End of time window (defaults to now).
            event_names: Filter to specific event names.
            resource_arn: Filter to events affecting this resource.

        Returns:
            List of CloudTrail events.
        """
        if not self._check_cloudtrail_access():
            logger.warning("CloudTrail not accessible, skipping event fetch")
            return []

        if end_time is None:
            end_time = datetime.now(timezone.utc)

        # Build the lookup-events command
        cmd = [
            "aws",
            "cloudtrail",
            "lookup-events",
            "--start-time",
            start_time.isoformat(),
            "--end-time",
            end_time.isoformat(),
            "--max-results",
            "50",
            "--output",
            "json",
            "--region",
            self.aws_region,
        ]

        # Add lookup attributes for filtering
        lookup_attributes = []
        if event_names and len(event_names) == 1:
            # CloudTrail lookup only supports single event name filter
            lookup_attributes.append(
                {"AttributeKey": "EventName", "AttributeValue": event_names[0]}
            )
        if resource_arn:
            lookup_attributes.append(
                {"AttributeKey": "ResourceName", "AttributeValue": resource_arn}
            )

        if lookup_attributes:
            cmd.extend(["--lookup-attributes", json.dumps(lookup_attributes)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )

            if result.returncode != 0:
                logger.error(f"CloudTrail lookup failed: {result.stderr}")
                return []

            response = json.loads(result.stdout)
            events = response.get("Events", [])

            # Parse CloudTrailEvent JSON for each event
            parsed_events = []
            for event in events:
                try:
                    cloud_trail_event = json.loads(event.get("CloudTrailEvent", "{}"))
                    parsed_events.append({
                        "event_id": event.get("EventId"),
                        "event_source": event.get("EventSource"),
                        "event_name": event.get("EventName"),
                        "event_time": event.get("EventTime"),
                        "username": event.get("Username"),
                        "resources": event.get("Resources", []),
                        "source_ip": cloud_trail_event.get("sourceIPAddress"),
                        "user_identity": cloud_trail_event.get("userIdentity"),
                        "request_parameters": cloud_trail_event.get("requestParameters"),
                        "response_elements": cloud_trail_event.get("responseElements"),
                        "error_code": cloud_trail_event.get("errorCode"),
                        "error_message": cloud_trail_event.get("errorMessage"),
                    })
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse CloudTrailEvent: {event.get('EventId')}")
                    continue

            # Filter by event names if multiple were specified
            if event_names and len(event_names) > 1:
                parsed_events = [
                    e for e in parsed_events if e.get("event_name") in event_names
                ]

            logger.info(f"Fetched {len(parsed_events)} CloudTrail events")
            return parsed_events

        except subprocess.TimeoutExpired:
            logger.error("CloudTrail lookup timed out")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CloudTrail response: {e}")
            return []
        except Exception as e:
            logger.error(f"Error fetching CloudTrail events: {e}")
            return []

    def correlate_finding(self, finding_id: int) -> list[dict]:
        """
        Correlate a finding with CloudTrail events.

        Args:
            finding_id: Database ID of the finding to correlate.

        Returns:
            List of correlation results.
        """
        conn = self._get_connection()
        try:
            cur = conn.cursor()

            # Get finding details
            cur.execute(
                """
                SELECT id, finding_id, tool, cloud_provider, account_id, region,
                       resource_type, resource_id, resource_name, severity, title,
                       description, metadata, first_seen, last_seen
                FROM findings
                WHERE id = %s
                """,
                (finding_id,),
            )
            finding = cur.fetchone()

            if not finding:
                logger.warning(f"Finding {finding_id} not found")
                return []

            # Determine correlation type based on finding
            correlation_type = self._determine_correlation_type(dict(finding))

            if not correlation_type:
                logger.info(f"No correlation type determined for finding {finding_id}")
                return []

            # Get event patterns for this correlation type
            pattern = CORRELATION_PATTERNS.get(correlation_type)
            if not pattern:
                return []

            # Calculate time window (default 24 hours before and after first_seen)
            first_seen = finding.get("first_seen") or datetime.now(timezone.utc)
            if isinstance(first_seen, str):
                first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            elif first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)

            start_time = first_seen - timedelta(hours=24)
            end_time = first_seen + timedelta(hours=24)

            # Fetch relevant CloudTrail events
            events = self.fetch_cloudtrail_events(
                start_time=start_time,
                end_time=end_time,
                event_names=pattern["events"],
                resource_arn=finding.get("resource_id"),
            )

            # Match events to finding
            correlations = self._match_events_to_finding(dict(finding), events)

            # Store correlations
            self._store_correlations(finding_id, correlations, conn)

            return correlations

        except Exception as e:
            logger.error(f"Error correlating finding {finding_id}: {e}")
            return []
        finally:
            conn.close()

    def correlate_attack_path(self, attack_path_id: int) -> list[dict]:
        """
        Correlate an attack path with CloudTrail events.

        Args:
            attack_path_id: Database ID of the attack path.

        Returns:
            List of correlation results.
        """
        conn = self._get_connection()
        try:
            cur = conn.cursor()

            # Get attack path details
            cur.execute(
                """
                SELECT id, path_id, scan_id, name, description, entry_point_type,
                       entry_point_id, entry_point_name, target_type, nodes, edges,
                       finding_ids, risk_score, exploitability, mitre_tactics, created_at
                FROM attack_paths
                WHERE id = %s
                """,
                (attack_path_id,),
            )
            path = cur.fetchone()

            if not path:
                logger.warning(f"Attack path {attack_path_id} not found")
                return []

            # Get findings associated with this path
            finding_ids = path.get("finding_ids") or []
            if not finding_ids:
                return []

            all_correlations = []
            for finding_id in finding_ids:
                correlations = self.correlate_finding(finding_id)
                for corr in correlations:
                    corr["attack_path_id"] = attack_path_id
                all_correlations.extend(correlations)

            return all_correlations

        except Exception as e:
            logger.error(f"Error correlating attack path {attack_path_id}: {e}")
            return []
        finally:
            conn.close()

    def correlate_privesc_path(self, privesc_path_id: int) -> list[dict]:
        """
        Correlate a privilege escalation path with CloudTrail events.

        Args:
            privesc_path_id: Database ID of the privesc path.

        Returns:
            List of correlation results.
        """
        conn = self._get_connection()
        try:
            cur = conn.cursor()

            # Get privesc path details
            cur.execute(
                """
                SELECT id, path_id, scan_id, cloud_provider, account_id,
                       source_principal_type, source_principal_arn, source_principal_name,
                       target_principal_type, target_principal_arn, target_principal_name,
                       escalation_method, risk_score, exploitability, finding_ids, created_at
                FROM privesc_paths
                WHERE id = %s
                """,
                (privesc_path_id,),
            )
            path = cur.fetchone()

            if not path:
                logger.warning(f"Privesc path {privesc_path_id} not found")
                return []

            # Focus on privilege escalation events
            pattern = CORRELATION_PATTERNS.get("privesc", {})
            event_names = pattern.get("events", [])

            # Calculate time window
            created_at = path.get("created_at") or datetime.now(timezone.utc)
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            elif created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)

            start_time = created_at - timedelta(hours=48)
            end_time = datetime.now(timezone.utc)

            # Fetch events related to source principal
            events = self.fetch_cloudtrail_events(
                start_time=start_time,
                end_time=end_time,
                event_names=event_names,
                resource_arn=path.get("source_principal_arn"),
            )

            # Match events to privesc path
            correlations = []
            for event in events:
                # Check if event involves the source or target principal
                user_identity = event.get("user_identity") or {}
                event_principal_arn = user_identity.get("arn", "")

                source_match = (
                    path.get("source_principal_arn")
                    and path["source_principal_arn"] in event_principal_arn
                )
                target_match = (
                    path.get("target_principal_arn")
                    and path["target_principal_arn"] in str(event.get("request_parameters", ""))
                )

                if source_match or target_match:
                    confidence = self._calculate_confidence(
                        {"resource_id": path.get("source_principal_arn")}, event
                    )
                    correlation = {
                        "correlation_id": self._generate_correlation_id(
                            privesc_path_id, event.get("event_id")
                        ),
                        "privesc_path_id": privesc_path_id,
                        "event": event,
                        "correlation_type": "privesc",
                        "confidence_score": confidence,
                        "confirms_exploitability": confidence >= 70,
                        "anomaly_detected": self._is_anomalous_event(event),
                        "analysis_notes": f"Matched {event.get('event_name')} event",
                    }
                    correlations.append(correlation)

            # Store correlations
            self._store_privesc_correlations(privesc_path_id, correlations, conn)

            return correlations

        except Exception as e:
            logger.error(f"Error correlating privesc path {privesc_path_id}: {e}")
            return []
        finally:
            conn.close()

    def _determine_correlation_type(self, finding: dict) -> str | None:
        """
        Determine the correlation type based on finding characteristics.

        Args:
            finding: Finding dictionary.

        Returns:
            Correlation type string or None.
        """
        title = (finding.get("title") or "").lower()
        resource_type = (finding.get("resource_type") or "").lower()
        description = (finding.get("description") or "").lower()

        # Check for privilege escalation indicators
        if any(
            kw in title or kw in description
            for kw in ["privilege", "escalat", "iam policy", "assume role", "passrole"]
        ):
            return "privesc"

        # Check for data access indicators
        if any(
            kw in title or kw in description or kw in resource_type
            for kw in ["s3", "bucket", "object", "data", "storage"]
        ):
            return "data_access"

        # Check for credential indicators
        if any(
            kw in title or kw in description
            for kw in ["credential", "access key", "secret", "token", "password"]
        ):
            return "credential_usage"

        # Check for resource modification
        if any(
            kw in resource_type for kw in ["ec2", "instance", "security group", "vpc"]
        ):
            return "resource_modification"

        # Check for secrets
        if "secret" in title or "secret" in resource_type:
            return "secrets_access"

        # Check for Lambda
        if "lambda" in title or "lambda" in resource_type:
            return "lambda_execution"

        return None

    def _match_events_to_finding(
        self, finding: dict, events: list[dict]
    ) -> list[dict]:
        """
        Match CloudTrail events to a finding.

        Args:
            finding: Finding dictionary.
            events: List of CloudTrail events.

        Returns:
            List of correlation dictionaries.
        """
        correlations = []

        for event in events:
            # Check for resource ARN match
            resource_match = False
            finding_resource = finding.get("resource_id") or ""

            # Check in event resources
            for resource in event.get("resources", []):
                if finding_resource and finding_resource in str(resource.get("ResourceName", "")):
                    resource_match = True
                    break

            # Check in request parameters
            if not resource_match and finding_resource:
                request_params = str(event.get("request_parameters", ""))
                if finding_resource in request_params:
                    resource_match = True

            if resource_match:
                confidence = self._calculate_confidence(finding, event)
                correlation = {
                    "correlation_id": self._generate_correlation_id(
                        finding.get("id"), event.get("event_id")
                    ),
                    "finding_id": finding.get("id"),
                    "event": event,
                    "correlation_type": self._determine_correlation_type(finding) or "unknown",
                    "confidence_score": confidence,
                    "confirms_exploitability": confidence >= 70,
                    "anomaly_detected": self._is_anomalous_event(event),
                    "analysis_notes": self._generate_analysis_notes(finding, event),
                }
                correlations.append(correlation)

        return correlations

    def _calculate_confidence(self, finding: dict, event: dict) -> int:
        """
        Calculate confidence score for a correlation (0-100).

        Higher confidence for:
        - Exact ARN matches
        - Time proximity to finding
        - Matching principals
        - Successful (non-error) events

        Args:
            finding: Finding dictionary.
            event: CloudTrail event dictionary.

        Returns:
            Confidence score 0-100.
        """
        confidence = 50  # Base confidence

        # ARN match boost
        finding_resource = finding.get("resource_id") or ""
        if finding_resource:
            for resource in event.get("resources", []):
                if finding_resource == resource.get("ResourceName"):
                    confidence += 25  # Exact match
                    break
                elif finding_resource in str(resource.get("ResourceName", "")):
                    confidence += 15  # Partial match

        # Success vs error
        if not event.get("error_code"):
            confidence += 10  # Successful event

        # Account ID match
        user_identity = event.get("user_identity") or {}
        event_account = user_identity.get("accountId")
        finding_account = finding.get("account_id")
        if event_account and finding_account and event_account == finding_account:
            confidence += 10

        # Anomaly detection penalty (could be false positive)
        if self._is_anomalous_event(event):
            confidence += 5  # Anomalous events are more interesting but could be noise

        return min(100, max(0, confidence))

    def _is_anomalous_event(self, event: dict) -> bool:
        """
        Detect if an event is anomalous.

        Checks for:
        - Unusual source IPs
        - Off-hours activity
        - Error events (potential probing)
        - Root account usage

        Args:
            event: CloudTrail event dictionary.

        Returns:
            True if event appears anomalous.
        """
        # Check for off-hours activity
        event_time = event.get("event_time")
        if event_time:
            if isinstance(event_time, str):
                try:
                    event_dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                    hour = event_dt.hour
                    if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
                        return True
                except ValueError:
                    pass

        # Check for suspicious source IP patterns
        source_ip = event.get("source_ip") or ""
        for pattern in SUSPICIOUS_IP_PATTERNS:
            if pattern in source_ip.lower():
                return True

        # Check for root account usage
        user_identity = event.get("user_identity") or {}
        if user_identity.get("type") == "Root":
            return True

        # Check for access denied errors (potential probing)
        error_code = event.get("error_code") or ""
        if "AccessDenied" in error_code:
            return True

        return False

    def _detect_anomalies(self, events: list[dict]) -> list[dict]:
        """
        Detect anomalous events from a list.

        Args:
            events: List of CloudTrail events.

        Returns:
            List of anomalous events with reasons.
        """
        anomalies = []
        for event in events:
            if self._is_anomalous_event(event):
                reasons = []

                # Determine reasons
                event_time = event.get("event_time")
                if event_time and isinstance(event_time, str):
                    try:
                        event_dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                        hour = event_dt.hour
                        if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
                            reasons.append("Off-hours activity")
                    except ValueError:
                        pass

                source_ip = event.get("source_ip") or ""
                for pattern in SUSPICIOUS_IP_PATTERNS:
                    if pattern in source_ip.lower():
                        reasons.append(f"Suspicious IP pattern: {pattern}")

                user_identity = event.get("user_identity") or {}
                if user_identity.get("type") == "Root":
                    reasons.append("Root account usage")

                error_code = event.get("error_code") or ""
                if "AccessDenied" in error_code:
                    reasons.append("Access denied (potential probing)")

                anomalies.append({
                    "event": event,
                    "suspicion_reasons": reasons,
                    "severity": "high" if len(reasons) > 1 else "medium",
                })

        return anomalies

    def _generate_analysis_notes(self, finding: dict, event: dict) -> str:
        """Generate analysis notes for a correlation."""
        notes = []

        notes.append(f"Event: {event.get('event_name')} from {event.get('event_source')}")

        if event.get("error_code"):
            notes.append(f"Error: {event.get('error_code')}")
        else:
            notes.append("Event succeeded")

        if self._is_anomalous_event(event):
            notes.append("Anomalous indicators detected")

        return "; ".join(notes)

    def _generate_correlation_id(self, finding_id: Any, event_id: str | None) -> str:
        """Generate a unique correlation ID."""
        content = f"{finding_id}:{event_id}:{datetime.now(timezone.utc).isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _store_correlations(
        self, finding_id: int, correlations: list[dict], conn
    ) -> None:
        """Store finding correlations in database."""
        if not correlations:
            return

        try:
            cur = conn.cursor()

            # Ensure runtime_correlations table exists
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_correlations (
                    id SERIAL PRIMARY KEY,
                    correlation_id VARCHAR(64) UNIQUE NOT NULL,
                    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
                    attack_path_id INTEGER REFERENCES attack_paths(id) ON DELETE CASCADE,
                    privesc_path_id INTEGER REFERENCES privesc_paths(id) ON DELETE CASCADE,
                    event_data JSONB NOT NULL,
                    correlation_type VARCHAR(64) NOT NULL,
                    confidence_score INTEGER NOT NULL DEFAULT 50,
                    confirms_exploitability BOOLEAN DEFAULT FALSE,
                    anomaly_detected BOOLEAN DEFAULT FALSE,
                    analysis_notes TEXT,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
                """
            )

            # Create indexes if not exist
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_runtime_correlations_finding
                ON runtime_correlations(finding_id)
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_runtime_correlations_attack_path
                ON runtime_correlations(attack_path_id)
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_runtime_correlations_privesc
                ON runtime_correlations(privesc_path_id)
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_runtime_correlations_confirmed
                ON runtime_correlations(confirms_exploitability) WHERE confirms_exploitability = true
                """
            )

            for corr in correlations:
                cur.execute(
                    """
                    INSERT INTO runtime_correlations (
                        correlation_id, finding_id, attack_path_id, privesc_path_id,
                        event_data, correlation_type, confidence_score,
                        confirms_exploitability, anomaly_detected, analysis_notes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (correlation_id) DO UPDATE SET
                        confidence_score = EXCLUDED.confidence_score,
                        confirms_exploitability = EXCLUDED.confirms_exploitability,
                        anomaly_detected = EXCLUDED.anomaly_detected,
                        analysis_notes = EXCLUDED.analysis_notes,
                        updated_at = NOW()
                    """,
                    (
                        corr["correlation_id"],
                        corr.get("finding_id"),
                        corr.get("attack_path_id"),
                        corr.get("privesc_path_id"),
                        Json(corr.get("event")),
                        corr["correlation_type"],
                        corr["confidence_score"],
                        corr["confirms_exploitability"],
                        corr["anomaly_detected"],
                        corr.get("analysis_notes"),
                    ),
                )

            conn.commit()
            logger.info(f"Stored {len(correlations)} correlations for finding {finding_id}")

        except Exception as e:
            logger.error(f"Error storing correlations: {e}")
            conn.rollback()

    def _store_privesc_correlations(
        self, privesc_path_id: int, correlations: list[dict], conn
    ) -> None:
        """Store privesc path correlations in database."""
        # Reuse the same table, just with privesc_path_id set
        if not correlations:
            return

        try:
            cur = conn.cursor()

            # Ensure table exists (same as _store_correlations)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_correlations (
                    id SERIAL PRIMARY KEY,
                    correlation_id VARCHAR(64) UNIQUE NOT NULL,
                    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
                    attack_path_id INTEGER REFERENCES attack_paths(id) ON DELETE CASCADE,
                    privesc_path_id INTEGER REFERENCES privesc_paths(id) ON DELETE CASCADE,
                    event_data JSONB NOT NULL,
                    correlation_type VARCHAR(64) NOT NULL,
                    confidence_score INTEGER NOT NULL DEFAULT 50,
                    confirms_exploitability BOOLEAN DEFAULT FALSE,
                    anomaly_detected BOOLEAN DEFAULT FALSE,
                    analysis_notes TEXT,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
                """
            )

            for corr in correlations:
                cur.execute(
                    """
                    INSERT INTO runtime_correlations (
                        correlation_id, finding_id, attack_path_id, privesc_path_id,
                        event_data, correlation_type, confidence_score,
                        confirms_exploitability, anomaly_detected, analysis_notes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (correlation_id) DO UPDATE SET
                        confidence_score = EXCLUDED.confidence_score,
                        confirms_exploitability = EXCLUDED.confirms_exploitability,
                        anomaly_detected = EXCLUDED.anomaly_detected,
                        analysis_notes = EXCLUDED.analysis_notes,
                        updated_at = NOW()
                    """,
                    (
                        corr["correlation_id"],
                        corr.get("finding_id"),
                        corr.get("attack_path_id"),
                        corr.get("privesc_path_id"),
                        Json(corr.get("event")),
                        corr["correlation_type"],
                        corr["confidence_score"],
                        corr["confirms_exploitability"],
                        corr["anomaly_detected"],
                        corr.get("analysis_notes"),
                    ),
                )

            conn.commit()
            logger.info(
                f"Stored {len(correlations)} correlations for privesc path {privesc_path_id}"
            )

        except Exception as e:
            logger.error(f"Error storing privesc correlations: {e}")
            conn.rollback()

    def get_suspicious_events(self, hours: int = 24) -> list[dict]:
        """
        Get suspicious events from CloudTrail.

        Args:
            hours: Number of hours to look back.

        Returns:
            List of suspicious events with reasons.
        """
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        end_time = datetime.now(timezone.utc)

        # Fetch events from all correlation patterns
        all_events = []
        for pattern_name, pattern in CORRELATION_PATTERNS.items():
            events = self.fetch_cloudtrail_events(
                start_time=start_time,
                end_time=end_time,
                event_names=pattern["events"][:5],  # Limit to first 5 to avoid too many queries
            )
            all_events.extend(events)

        # Detect anomalies
        anomalies = self._detect_anomalies(all_events)

        return anomalies

    def get_confirmed_exploits(self, scan_id: str | None = None) -> list[dict]:
        """
        Get findings confirmed by runtime events.

        Args:
            scan_id: Optional scan ID to filter by.

        Returns:
            List of confirmed exploits with correlation details.
        """
        conn = self._get_connection()
        try:
            cur = conn.cursor()

            query = """
                SELECT
                    rc.id,
                    rc.correlation_id,
                    rc.finding_id,
                    rc.attack_path_id,
                    rc.privesc_path_id,
                    rc.event_data,
                    rc.correlation_type,
                    rc.confidence_score,
                    rc.analysis_notes,
                    rc.created_at,
                    f.title AS finding_title,
                    f.severity AS finding_severity,
                    f.resource_id AS finding_resource
                FROM runtime_correlations rc
                LEFT JOIN findings f ON rc.finding_id = f.id
                WHERE rc.confirms_exploitability = true
            """

            params = []
            if scan_id:
                query += " AND f.scan_id = %s"
                params.append(scan_id)

            query += " ORDER BY rc.confidence_score DESC, rc.created_at DESC"

            cur.execute(query, params)
            results = cur.fetchall()

            confirmed = []
            for row in results:
                confirmed.append({
                    "finding_id": row["finding_id"],
                    "finding_title": row["finding_title"],
                    "finding_severity": row["finding_severity"],
                    "finding_resource": row["finding_resource"],
                    "correlation": {
                        "correlation_id": row["correlation_id"],
                        "event": row["event_data"],
                        "correlation_type": row["correlation_type"],
                        "confidence_score": row["confidence_score"],
                        "analysis_notes": row["analysis_notes"],
                    },
                    "confirmed_at": row["created_at"],
                })

            return confirmed

        except Exception as e:
            logger.error(f"Error fetching confirmed exploits: {e}")
            return []
        finally:
            conn.close()

    def get_correlations_for_finding(self, finding_id: int) -> list[dict]:
        """
        Get all runtime correlations for a specific finding.

        Args:
            finding_id: Database ID of the finding.

        Returns:
            List of correlation dictionaries.
        """
        conn = self._get_connection()
        try:
            cur = conn.cursor()

            cur.execute(
                """
                SELECT
                    correlation_id, finding_id, attack_path_id, privesc_path_id,
                    event_data, correlation_type, confidence_score,
                    confirms_exploitability, anomaly_detected, analysis_notes, created_at
                FROM runtime_correlations
                WHERE finding_id = %s
                ORDER BY confidence_score DESC
                """,
                (finding_id,),
            )

            results = cur.fetchall()
            return [dict(row) for row in results]

        except Exception as e:
            logger.error(f"Error fetching correlations for finding {finding_id}: {e}")
            return []
        finally:
            conn.close()


def main():
    """Main entry point for runtime correlation analysis."""
    correlator = RuntimeCorrelator()

    # Check CloudTrail access
    if not correlator._check_cloudtrail_access():
        print("CloudTrail access not available. Exiting.")
        return

    # Get suspicious events from last 24 hours
    print("\nFetching suspicious events from last 24 hours...")
    suspicious = correlator.get_suspicious_events(hours=24)

    print(f"\nFound {len(suspicious)} suspicious events:")
    for event in suspicious[:10]:  # Show first 10
        e = event["event"]
        print(f"  - {e.get('event_name')} from {e.get('source_ip')}")
        print(f"    Reasons: {', '.join(event['suspicion_reasons'])}")

    # Get confirmed exploits
    print("\nFetching confirmed exploits...")
    confirmed = correlator.get_confirmed_exploits()

    print(f"\nFound {len(confirmed)} confirmed exploits:")
    for exploit in confirmed[:10]:  # Show first 10
        print(f"  - {exploit['finding_title']}")
        print(f"    Confidence: {exploit['correlation']['confidence_score']}%")


if __name__ == "__main__":
    main()
