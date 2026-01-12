#!/usr/bin/env python3
"""Analyze ScoutSuite report structure."""

import json


def main():
    report_path = "/reports/scoutsuite/aws/scoutsuite-results/scoutsuite_results-aws-default.js"

    with open(report_path) as f:
        content = f.read()

    # Remove JS variable assignment
    json_str = content.split("=", 1)[1].strip()
    data = json.loads(json_str)

    print(f"Account ID: {data.get('aws_account_id')}")
    print()

    # Examine all services' findings
    services = data.get("services", {})
    for service_name, service_data in services.items():
        findings = service_data.get("findings", {})
        for finding_id, finding in findings.items():
            flagged = finding.get("flagged_items", 0)
            if flagged > 0:
                items = finding.get("items", [])
                print(f"Service: {service_name}")
                print(f"  Finding ID: {finding_id}")
                print(f"  Description: {finding.get('description')}")
                print(f"  Rationale: {finding.get('rationale', '')[:150]}...")
                print(f"  Level: {finding.get('level')}")
                print(f"  Flagged items: {flagged}")
                print(f"  Items array ({len(items)} items):")
                for item in items[:5]:
                    print(f"    - {item}")
                if len(items) > 5:
                    print(f"    ... and {len(items) - 5} more")
                print()


if __name__ == "__main__":
    main()
