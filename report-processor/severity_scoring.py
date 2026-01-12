#!/usr/bin/env python3
"""
CVSS-Style Severity Scoring for Security Findings

This module provides risk scoring based on:
- Base severity from scanning tools
- Exploitability factors (Attack Vector, Attack Complexity, Privileges Required)
- Impact factors (Confidentiality, Integrity, Availability)
- Likelihood of exploitation (confirmed, likely, theoretical)

Scoring follows CVSS 3.1 methodology adapted for cloud security findings.
"""

import logging
import re

logger = logging.getLogger(__name__)


# =============================================================================
# CVSS-STYLE SCORING CONSTANTS
# =============================================================================

# Base Severity Scores (starting point from tool output)
BASE_SEVERITY_SCORES = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
    "informational": 1.0,
    "danger": 7.5,  # ScoutSuite mapping
    "warning": 5.0,  # ScoutSuite mapping
}

# Attack Vector (AV) - How is the vulnerability accessed?
ATTACK_VECTOR = {
    "network": 0.85,  # Remotely exploitable over internet
    "adjacent": 0.62,  # Requires network proximity
    "local": 0.55,  # Requires existing system access
    "physical": 0.20,  # Requires physical access
}

# Attack Complexity (AC) - How complex is exploitation?
ATTACK_COMPLEXITY = {
    "low": 0.77,  # Straightforward, repeatable
    "high": 0.44,  # Requires specific conditions
}

# Privileges Required (PR) - What access level needed?
PRIVILEGES_REQUIRED = {
    "none": 0.85,  # No authentication needed
    "low": 0.62,  # Basic user access
    "high": 0.27,  # Admin/elevated privileges
}

# User Interaction (UI) - Does it need victim action?
USER_INTERACTION = {
    "none": 0.85,  # No user action required
    "required": 0.62,  # User must click/interact
}

# Exploitation Likelihood Multiplier
EXPLOITATION_LIKELIHOOD = {
    "confirmed": 1.0,  # Known exploitable, tools/PoC exist
    "likely": 0.85,  # Documented technique, feasible
    "theoretical": 0.65,  # Possible but unproven in wild
    "unlikely": 0.40,  # Edge case, hard to exploit
}

# Impact Scores (CIA Triad)
IMPACT_SCORES = {
    "confidentiality": {"high": 0.56, "low": 0.22, "none": 0.0},
    "integrity": {"high": 0.56, "low": 0.22, "none": 0.0},
    "availability": {"high": 0.56, "low": 0.22, "none": 0.0},
}


# =============================================================================
# FINDING TYPE PROFILES
# =============================================================================

# Pre-defined profiles for common cloud security finding types
FINDING_PROFILES = {
    # Public Exposure - High exploitability
    "public_s3": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "likelihood": "confirmed",
        "confidentiality_impact": "high",
        "integrity_impact": "low",
        "availability_impact": "none",
    },
    "public_rds": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "low",  # Still need credentials
        "user_interaction": "none",
        "likelihood": "likely",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "high",
    },
    "open_security_group": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "likelihood": "confirmed",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "high",
    },
    "ssh_open_to_world": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "low",
        "user_interaction": "none",
        "likelihood": "confirmed",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "high",
    },
    "rdp_open_to_world": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "low",
        "user_interaction": "none",
        "likelihood": "confirmed",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "high",
    },
    # IAM Weaknesses
    "root_mfa_disabled": {
        "attack_vector": "network",
        "attack_complexity": "high",  # Need credentials first
        "privileges_required": "high",
        "user_interaction": "none",
        "likelihood": "likely",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "high",
    },
    "root_access_key": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",  # If key leaked
        "user_interaction": "none",
        "likelihood": "confirmed",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "high",
    },
    "overly_permissive_iam": {
        "attack_vector": "local",
        "attack_complexity": "low",
        "privileges_required": "low",
        "user_interaction": "none",
        "likelihood": "likely",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "low",
    },
    "iam_user_no_mfa": {
        "attack_vector": "network",
        "attack_complexity": "high",
        "privileges_required": "low",
        "user_interaction": "none",
        "likelihood": "likely",
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "low",
    },
    # Encryption/Data Protection
    "unencrypted_storage": {
        "attack_vector": "local",
        "attack_complexity": "high",
        "privileges_required": "high",
        "user_interaction": "none",
        "likelihood": "theoretical",
        "confidentiality_impact": "high",
        "integrity_impact": "none",
        "availability_impact": "none",
    },
    "unencrypted_rds": {
        "attack_vector": "local",
        "attack_complexity": "high",
        "privileges_required": "high",
        "user_interaction": "none",
        "likelihood": "theoretical",
        "confidentiality_impact": "high",
        "integrity_impact": "none",
        "availability_impact": "none",
    },
    # Logging/Monitoring
    "cloudtrail_disabled": {
        "attack_vector": "local",
        "attack_complexity": "high",
        "privileges_required": "high",
        "user_interaction": "none",
        "likelihood": "theoretical",
        "confidentiality_impact": "none",
        "integrity_impact": "low",
        "availability_impact": "none",
    },
    "no_logging": {
        "attack_vector": "local",
        "attack_complexity": "high",
        "privileges_required": "high",
        "user_interaction": "none",
        "likelihood": "unlikely",
        "confidentiality_impact": "none",
        "integrity_impact": "low",
        "availability_impact": "none",
    },
    # Default profile for unknown findings
    "default": {
        "attack_vector": "adjacent",
        "attack_complexity": "low",
        "privileges_required": "low",
        "user_interaction": "none",
        "likelihood": "likely",
        "confidentiality_impact": "low",
        "integrity_impact": "low",
        "availability_impact": "low",
    },
}


# =============================================================================
# FINDING TYPE DETECTION PATTERNS
# =============================================================================

FINDING_TYPE_PATTERNS = {
    # Public exposure patterns
    r"public.*s3|s3.*public|bucket.*public": "public_s3",
    r"public.*rds|rds.*public|database.*public": "public_rds",
    r"open.*security.*group|security.*group.*open|0\.0\.0\.0/0": "open_security_group",
    r"ssh.*open|port.*22.*open|ssh.*0\.0\.0\.0": "ssh_open_to_world",
    r"rdp.*open|port.*3389.*open|rdp.*0\.0\.0\.0": "rdp_open_to_world",
    # IAM patterns
    r"root.*mfa|mfa.*root|root.*multi.*factor": "root_mfa_disabled",
    r"root.*access.*key|access.*key.*root": "root_access_key",
    r"overly.*permissive|admin.*access|\*:\*|full.*access": "overly_permissive_iam",
    r"user.*no.*mfa|mfa.*not.*enabled|mfa.*disabled": "iam_user_no_mfa",
    # Encryption patterns
    r"unencrypted|encryption.*disabled|no.*encryption|not.*encrypted": "unencrypted_storage",
    r"rds.*encrypt|encrypt.*rds|database.*encrypt": "unencrypted_rds",
    # Logging patterns
    r"cloudtrail.*disabled|cloudtrail.*not.*enabled": "cloudtrail_disabled",
    r"logging.*disabled|no.*logging|access.*log.*disabled": "no_logging",
}


def detect_finding_type(finding: dict) -> str:
    """
    Detect the finding type based on title, description, and check_id.

    Args:
        finding: The finding dictionary

    Returns:
        The detected finding type key for FINDING_PROFILES
    """
    # Build searchable text from finding
    search_text = " ".join(
        [
            finding.get("check_title", ""),
            finding.get("title", ""),
            finding.get("check_id", ""),
            finding.get("description", ""),
        ]
    ).lower()

    # Try to match patterns
    for pattern, finding_type in FINDING_TYPE_PATTERNS.items():
        if re.search(pattern, search_text, re.IGNORECASE):
            return finding_type

    return "default"


def calculate_risk_score(
    finding: dict,
    base_severity: str | None = None,
) -> tuple[float, str, dict]:
    """
    Calculate CVSS-style risk score for a security finding.

    Args:
        finding: The finding dictionary
        base_severity: Optional override for base severity

    Returns:
        Tuple of (risk_score 0-100, adjusted_severity, scoring_details)
    """
    # Get base severity from finding or parameter
    raw_severity = base_severity or finding.get("severity", "medium")
    base_score = BASE_SEVERITY_SCORES.get(raw_severity.lower(), 5.0)

    # Detect finding type and get profile
    finding_type = detect_finding_type(finding)
    profile = FINDING_PROFILES.get(finding_type, FINDING_PROFILES["default"])

    # Get CVSS component values
    av = ATTACK_VECTOR.get(profile["attack_vector"], 0.62)
    ac = ATTACK_COMPLEXITY.get(profile["attack_complexity"], 0.77)
    pr = PRIVILEGES_REQUIRED.get(profile["privileges_required"], 0.62)
    ui = USER_INTERACTION.get(profile["user_interaction"], 0.85)

    # Get likelihood multiplier
    likelihood = EXPLOITATION_LIKELIHOOD.get(profile["likelihood"], 0.75)

    # Calculate Exploitability Score (CVSS formula: 8.22 × AV × AC × PR × UI)
    exploitability_score = 8.22 * av * ac * pr * ui * likelihood

    # Calculate Impact Score
    isc_base = 1 - (
        (1 - IMPACT_SCORES["confidentiality"].get(profile["confidentiality_impact"], 0.22))
        * (1 - IMPACT_SCORES["integrity"].get(profile["integrity_impact"], 0.22))
        * (1 - IMPACT_SCORES["availability"].get(profile["availability_impact"], 0.22))
    )

    # Impact sub-score (CVSS formula: 6.42 × ISCBase)
    impact_score = 6.42 * isc_base

    # Combine scores
    # If impact is 0, the whole score should be 0 (CVSS rule)
    if isc_base <= 0:
        final_cvss = 0.0
    else:
        # CVSS 3.1 formula for Scope Unchanged
        final_cvss = min(impact_score + exploitability_score, 10.0)

    # Convert to 0-100 scale and incorporate base severity
    # Weight: 40% base severity, 60% calculated CVSS
    risk_score = (base_score * 4 + final_cvss * 6) / 10  # This gives 0-10
    risk_score = risk_score * 10  # Scale to 0-100

    # Apply minimum floors based on finding type criticality
    min_floors = {
        "public_s3": 60,
        "public_rds": 70,
        "open_security_group": 65,
        "ssh_open_to_world": 70,
        "rdp_open_to_world": 70,
        "root_access_key": 85,
        "root_mfa_disabled": 75,
    }
    min_floor = min_floors.get(finding_type, 0)
    risk_score = max(risk_score, min_floor)

    # Cap at 100
    risk_score = min(risk_score, 100.0)

    # Determine adjusted severity based on risk score
    if risk_score >= 90:
        adjusted_severity = "critical"
    elif risk_score >= 70:
        adjusted_severity = "high"
    elif risk_score >= 40:
        adjusted_severity = "medium"
    elif risk_score >= 20:
        adjusted_severity = "low"
    else:
        adjusted_severity = "info"

    # Build scoring details for transparency
    scoring_details = {
        "finding_type": finding_type,
        "base_severity": raw_severity.lower(),
        "base_score": base_score,
        "attack_vector": profile["attack_vector"],
        "attack_vector_score": av,
        "attack_complexity": profile["attack_complexity"],
        "attack_complexity_score": ac,
        "privileges_required": profile["privileges_required"],
        "privileges_required_score": pr,
        "user_interaction": profile["user_interaction"],
        "user_interaction_score": ui,
        "exploitation_likelihood": profile["likelihood"],
        "likelihood_multiplier": likelihood,
        "exploitability_score": round(exploitability_score, 2),
        "impact_score": round(impact_score, 2),
        "confidentiality_impact": profile["confidentiality_impact"],
        "integrity_impact": profile["integrity_impact"],
        "availability_impact": profile["availability_impact"],
        "cvss_score": round(final_cvss, 1),
        "risk_score": round(risk_score, 1),
        "adjusted_severity": adjusted_severity,
    }

    return round(risk_score, 1), adjusted_severity, scoring_details


def get_severity_display(risk_score: float) -> str:
    """Get display severity label based on risk score."""
    if risk_score >= 90:
        return "CRITICAL"
    elif risk_score >= 70:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    else:
        return "INFO"


def enrich_finding_with_scoring(finding: dict) -> dict:
    """
    Enrich a finding dictionary with risk scoring data.

    Args:
        finding: The finding dictionary

    Returns:
        The enriched finding dictionary
    """
    risk_score, adjusted_severity, details = calculate_risk_score(finding)

    finding["risk_score"] = risk_score
    finding["cvss_score"] = details["cvss_score"]
    finding["original_severity"] = finding.get("severity", "medium")
    finding["severity"] = adjusted_severity
    finding["exploitation_likelihood"] = details["exploitation_likelihood"]
    finding["scoring_details"] = details

    return finding


if __name__ == "__main__":
    # Test the scoring system
    test_findings = [
        {
            "check_title": "S3 Bucket Public Access",
            "severity": "high",
            "description": "S3 bucket allows public read access",
        },
        {
            "check_title": "Security Group Open to World",
            "severity": "high",
            "description": "Security group allows 0.0.0.0/0 on all ports",
        },
        {
            "check_title": "Root MFA Not Enabled",
            "severity": "critical",
            "description": "Root account does not have MFA enabled",
        },
        {
            "check_title": "CloudTrail Not Enabled",
            "severity": "medium",
            "description": "CloudTrail logging is not enabled",
        },
        {
            "check_title": "S3 Bucket Encryption Disabled",
            "severity": "medium",
            "description": "S3 bucket does not have default encryption",
        },
    ]

    print("=" * 80)
    print("CVSS-Style Severity Scoring Test")
    print("=" * 80)

    for finding in test_findings:
        risk_score, adjusted_severity, details = calculate_risk_score(finding)
        print(f"\nFinding: {finding['check_title']}")
        print(f"  Original Severity: {finding['severity'].upper()}")
        print(f"  Finding Type: {details['finding_type']}")
        print(f"  CVSS Score: {details['cvss_score']}")
        print(f"  Risk Score: {risk_score}")
        print(f"  Adjusted Severity: {adjusted_severity.upper()}")
        print(f"  Exploitation Likelihood: {details['exploitation_likelihood']}")
