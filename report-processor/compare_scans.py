#!/usr/bin/env python3
"""Compare two scans for drift detection"""

import json
import argparse
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def compare_scans(baseline_path, current_path):
    """Compare two scan results"""
    
    with open(baseline_path) as f:
        baseline = json.load(f)
    
    with open(current_path) as f:
        current = json.load(f)
    
    # Find new issues
    baseline_ids = {f.get('finding_id') for f in baseline.get('findings', [])}
    current_ids = {f.get('finding_id') for f in current.get('findings', [])}
    
    new_issues = current_ids - baseline_ids
    resolved_issues = baseline_ids - current_ids
    
    print(f"New Issues: {len(new_issues)}")
    print(f"Resolved Issues: {len(resolved_issues)}")
    
    return {
        'new': list(new_issues),
        'resolved': list(resolved_issues),
        'total_baseline': len(baseline_ids),
        'total_current': len(current_ids)
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--current', required=True)
    args = parser.parse_args()
    
    result = compare_scans(args.baseline, args.current)
    print(json.dumps(result, indent=2))
