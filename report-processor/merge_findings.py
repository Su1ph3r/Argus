#!/usr/bin/env python3
"""Merge findings from multiple sources"""

import json
import logging

logger = logging.getLogger(__name__)

def merge_findings(scoutsuite_findings, prowler_findings):
    """Merge and deduplicate findings from different tools"""
    merged = {}
    
    # Process ScoutSuite findings
    for finding in scoutsuite_findings:
        key = f"{finding.get('resource_id')}_{finding.get('type')}"
        merged[key] = finding
    
    # Process Prowler findings
    for finding in prowler_findings:
        key = f"{finding.get('resource_id')}_{finding.get('check_id')}"
        if key not in merged:
            merged[key] = finding
    
    return list(merged.values())

if __name__ == "__main__":
    logger.info("Merge findings utility")
