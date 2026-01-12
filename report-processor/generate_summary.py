#!/usr/bin/env python3
"""
Generate summary statistics from audit findings
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import psycopg2
from tabulate import tabulate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SummaryGenerator:
    def __init__(self):
        self.db_config = {
            "host": os.environ.get("DB_HOST", "postgres"),
            "database": os.environ.get("DB_NAME", "cloudaudit"),
            "user": os.environ.get("DB_USER", "audituser"),
            "password": os.environ.get("DB_PASSWORD", "secretpassword"),
        }

    def generate(self):
        conn = psycopg2.connect(**self.db_config)
        cur = conn.cursor()

        # Get summary statistics
        cur.execute("""
            SELECT 
                tool,
                cloud_provider,
                COUNT(DISTINCT scan_id) as scans,
                COUNT(*) as total_findings,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
            FROM findings f
            JOIN scan_metadata s ON f.scan_id = s.scan_id
            WHERE s.scan_date > NOW() - INTERVAL '7 days'
            GROUP BY tool, cloud_provider
        """)

        results = cur.fetchall()

        # Format as table
        headers = [
            "Tool",
            "Provider",
            "Scans",
            "Total",
            "Critical",
            "High",
            "Medium",
            "Low",
        ]
        print("\n" + "=" * 80)
        print("CLOUD SECURITY AUDIT SUMMARY")
        print("=" * 80)
        print(tabulate(results, headers=headers, tablefmt="grid"))

        # Get top resources with issues
        cur.execute("""
            SELECT 
                resource_type,
                region,
                COUNT(*) as issue_count
            FROM findings
            WHERE severity IN ('CRITICAL', 'HIGH')
            GROUP BY resource_type, region
            ORDER BY issue_count DESC
            LIMIT 10
        """)

        top_resources = cur.fetchall()

        print("\nTOP RESOURCES WITH CRITICAL/HIGH ISSUES:")
        print(
            tabulate(
                top_resources,
                headers=["Resource Type", "Region", "Issues"],
                tablefmt="grid",
            )
        )

        conn.close()

        # Save to JSON
        summary = {
            "generated_at": datetime.now().isoformat(),
            "statistics": [dict(zip(headers, row, strict=False)) for row in results],
            "top_resources": [
                dict(zip(["resource_type", "region", "count"], row, strict=False))
                for row in top_resources
            ],
        }

        output_path = Path("/processed/summary_latest.json")
        with open(output_path, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Summary saved to {output_path}")


if __name__ == "__main__":
    generator = SummaryGenerator()
    generator.generate()
