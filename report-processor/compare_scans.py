#!/usr/bin/env python3
"""
Enhanced scan comparison with database support, severity tracking, and MTTR calculation.

Features:
- Compare scans by file path (backward compatible)
- Compare scans by database scan_id
- Compare scans by date range
- Severity breakdown analysis
- Mean Time To Resolution (MTTR) calculation
- Multiple output formats (json, table, csv)
"""

import json
import argparse
import os
import sys
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Optional imports for enhanced functionality
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScanComparator:
    """Compare security scans and calculate metrics."""

    def __init__(self):
        self.db_config = {
            'host': os.environ.get('DB_HOST', 'postgresql'),
            'database': os.environ.get('DB_NAME', 'security_audits'),
            'user': os.environ.get('DB_USER', 'auditor'),
            'password': os.environ.get('DB_PASSWORD', 'changeme'),
            'port': os.environ.get('DB_PORT', '5432')
        }
        self.conn = None

    def connect_db(self):
        """Connect to PostgreSQL database."""
        if not HAS_PSYCOPG2:
            raise ImportError("psycopg2 is required for database queries. Install with: pip install psycopg2-binary")

        if self.conn is None:
            self.conn = psycopg2.connect(**self.db_config)
        return self.conn

    def close_db(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def compare_files(self, baseline_path: str, current_path: str) -> Dict:
        """Compare two scan result files (backward compatible)."""
        with open(baseline_path) as f:
            baseline_data = json.load(f)

        with open(current_path) as f:
            current_data = json.load(f)

        # Extract findings - handle different formats
        baseline_findings = self._extract_findings(baseline_data)
        current_findings = self._extract_findings(current_data)

        return self._compare_findings(baseline_findings, current_findings)

    def _extract_findings(self, data: Any) -> List[Dict]:
        """Extract findings from various JSON formats."""
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            if 'findings' in data:
                return data['findings']
            elif 'results' in data:
                return data['results']
        return []

    def compare_by_scan_ids(self, baseline_id: str, current_id: str) -> Dict:
        """Compare two scans from database by scan_id."""
        conn = self.connect_db()

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get baseline findings
            cur.execute("""
                SELECT finding_id, severity, status, resource_type, resource_id,
                       title, first_seen, updated_at
                FROM findings
                WHERE scan_id = %s
            """, (baseline_id,))
            baseline_findings = cur.fetchall()

            # Get current findings
            cur.execute("""
                SELECT finding_id, severity, status, resource_type, resource_id,
                       title, first_seen, updated_at
                FROM findings
                WHERE scan_id = %s
            """, (current_id,))
            current_findings = cur.fetchall()

        return self._compare_findings(baseline_findings, current_findings)

    def compare_by_dates(self, baseline_date: str, current_date: str,
                         tool: Optional[str] = None) -> Dict:
        """Compare scans by date range."""
        conn = self.connect_db()

        base_query = """
            SELECT f.finding_id, f.severity, f.status, f.resource_type,
                   f.resource_id, f.title, f.first_seen, f.updated_at
            FROM findings f
            JOIN scans s ON f.scan_id = s.scan_id
            WHERE DATE(s.started_at) = %s
        """

        params_baseline = [baseline_date]
        params_current = [current_date]

        if tool:
            base_query += " AND s.tool = %s"
            params_baseline.append(tool)
            params_current.append(tool)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(base_query, params_baseline)
            baseline_findings = cur.fetchall()

            cur.execute(base_query, params_current)
            current_findings = cur.fetchall()

        return self._compare_findings(baseline_findings, current_findings)

    def _compare_findings(self, baseline: List, current: List) -> Dict:
        """Compare two sets of findings and compute metrics."""
        # Build ID sets
        baseline_ids = {self._get_finding_id(f) for f in baseline}
        current_ids = {self._get_finding_id(f) for f in current}

        new_ids = current_ids - baseline_ids
        resolved_ids = baseline_ids - current_ids
        persistent_ids = baseline_ids & current_ids

        # Build lookup dictionaries
        baseline_lookup = {self._get_finding_id(f): f for f in baseline}
        current_lookup = {self._get_finding_id(f): f for f in current}

        # Get new findings with details
        new_findings = [current_lookup[fid] for fid in new_ids if fid in current_lookup]
        resolved_findings = [baseline_lookup[fid] for fid in resolved_ids if fid in baseline_lookup]

        # Severity breakdown
        severity_breakdown = self._get_severity_breakdown(new_findings, resolved_findings)

        # Check for severity changes in persistent findings
        severity_changes = self._detect_severity_changes(
            persistent_ids, baseline_lookup, current_lookup
        )

        result = {
            'summary': {
                'total_baseline': len(baseline_ids),
                'total_current': len(current_ids),
                'new_count': len(new_ids),
                'resolved_count': len(resolved_ids),
                'persistent_count': len(persistent_ids)
            },
            'new_issues': list(new_ids),
            'resolved_issues': list(resolved_ids),
            'severity_breakdown': severity_breakdown,
            'severity_changes': severity_changes,
            'comparison_time': datetime.now().isoformat()
        }

        return result

    def _get_finding_id(self, finding: Any) -> str:
        """Extract finding ID from various formats."""
        if isinstance(finding, dict):
            return finding.get('finding_id') or finding.get('id') or finding.get('CheckID', '')
        return str(finding)

    def _get_severity(self, finding: Any) -> str:
        """Extract severity from finding."""
        if isinstance(finding, dict):
            return (finding.get('severity') or finding.get('Severity') or 'unknown').lower()
        return 'unknown'

    def _get_severity_breakdown(self, new_findings: List, resolved_findings: List) -> Dict:
        """Break down findings by severity level."""
        severities = ['critical', 'high', 'medium', 'low', 'info']

        new_by_severity = {s: 0 for s in severities}
        resolved_by_severity = {s: 0 for s in severities}

        for f in new_findings:
            sev = self._get_severity(f)
            if sev in new_by_severity:
                new_by_severity[sev] += 1

        for f in resolved_findings:
            sev = self._get_severity(f)
            if sev in resolved_by_severity:
                resolved_by_severity[sev] += 1

        return {
            'new': new_by_severity,
            'resolved': resolved_by_severity
        }

    def _detect_severity_changes(self, persistent_ids: set,
                                  baseline_lookup: Dict,
                                  current_lookup: Dict) -> List[Dict]:
        """Detect severity escalations/downgrades in persistent findings."""
        changes = []

        for fid in persistent_ids:
            if fid in baseline_lookup and fid in current_lookup:
                old_sev = self._get_severity(baseline_lookup[fid])
                new_sev = self._get_severity(current_lookup[fid])

                if old_sev != new_sev:
                    changes.append({
                        'finding_id': fid,
                        'old_severity': old_sev,
                        'new_severity': new_sev,
                        'change': 'escalated' if self._severity_rank(new_sev) < self._severity_rank(old_sev) else 'downgraded'
                    })

        return changes

    def _severity_rank(self, severity: str) -> int:
        """Return numeric rank for severity (lower = more severe)."""
        ranks = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        return ranks.get(severity.lower(), 6)

    def calculate_mttr(self, severity_filter: Optional[str] = None) -> Dict:
        """Calculate Mean Time To Resolution metrics."""
        conn = self.connect_db()

        query = """
            SELECT
                severity,
                COUNT(*) as resolved_count,
                AVG(EXTRACT(EPOCH FROM (updated_at - first_seen))/3600) as avg_hours,
                MIN(EXTRACT(EPOCH FROM (updated_at - first_seen))/3600) as min_hours,
                MAX(EXTRACT(EPOCH FROM (updated_at - first_seen))/3600) as max_hours
            FROM findings
            WHERE status = 'closed'
            AND first_seen IS NOT NULL
            AND updated_at IS NOT NULL
        """

        params = []
        if severity_filter:
            query += " AND severity = %s"
            params.append(severity_filter.lower())

        query += " GROUP BY severity ORDER BY severity"

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            results = cur.fetchall()

        mttr_data = {}
        for row in results:
            mttr_data[row['severity']] = {
                'resolved_count': row['resolved_count'],
                'avg_hours': round(float(row['avg_hours'] or 0), 2),
                'avg_days': round(float(row['avg_hours'] or 0) / 24, 2),
                'min_hours': round(float(row['min_hours'] or 0), 2),
                'max_hours': round(float(row['max_hours'] or 0), 2)
            }

        return mttr_data


def format_output(data: Dict, output_format: str) -> str:
    """Format comparison results for output."""
    if output_format == 'json':
        return json.dumps(data, indent=2, default=str)

    elif output_format == 'csv':
        # CSV output for severity breakdown
        output = []
        writer = csv.writer(sys.stdout)
        writer.writerow(['Category', 'Severity', 'Count'])

        if 'severity_breakdown' in data:
            for sev, count in data['severity_breakdown'].get('new', {}).items():
                writer.writerow(['New', sev, count])
            for sev, count in data['severity_breakdown'].get('resolved', {}).items():
                writer.writerow(['Resolved', sev, count])

        return ''  # CSV written directly to stdout

    else:  # table format
        if not HAS_TABULATE:
            # Fallback to simple text output
            lines = [
                "=" * 50,
                "Scan Comparison Results",
                "=" * 50,
                "",
                "Summary:",
                f"  Baseline findings: {data['summary']['total_baseline']}",
                f"  Current findings:  {data['summary']['total_current']}",
                f"  New issues:        {data['summary']['new_count']}",
                f"  Resolved issues:   {data['summary']['resolved_count']}",
                f"  Persistent:        {data['summary']['persistent_count']}",
                "",
                "Severity Breakdown (New):"
            ]

            for sev, count in data.get('severity_breakdown', {}).get('new', {}).items():
                lines.append(f"  {sev.capitalize():10} {count}")

            lines.append("")
            lines.append("Severity Breakdown (Resolved):")

            for sev, count in data.get('severity_breakdown', {}).get('resolved', {}).items():
                lines.append(f"  {sev.capitalize():10} {count}")

            if data.get('severity_changes'):
                lines.append("")
                lines.append("Severity Changes:")
                for change in data['severity_changes']:
                    lines.append(f"  {change['finding_id']}: {change['old_severity']} -> {change['new_severity']} ({change['change']})")

            return '\n'.join(lines)

        # Use tabulate for nice table output
        lines = ["", "=== Scan Comparison Results ===", ""]

        # Summary table
        summary_rows = [
            ['Baseline findings', data['summary']['total_baseline']],
            ['Current findings', data['summary']['total_current']],
            ['New issues', data['summary']['new_count']],
            ['Resolved issues', data['summary']['resolved_count']],
            ['Persistent', data['summary']['persistent_count']]
        ]
        lines.append(tabulate(summary_rows, headers=['Metric', 'Count'], tablefmt='simple'))
        lines.append("")

        # Severity breakdown table
        sev_rows = []
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            new_count = data.get('severity_breakdown', {}).get('new', {}).get(sev, 0)
            resolved_count = data.get('severity_breakdown', {}).get('resolved', {}).get(sev, 0)
            sev_rows.append([sev.capitalize(), new_count, resolved_count])

        lines.append("Severity Breakdown:")
        lines.append(tabulate(sev_rows, headers=['Severity', 'New', 'Resolved'], tablefmt='simple'))

        # Severity changes
        if data.get('severity_changes'):
            lines.append("")
            lines.append("Severity Changes:")
            change_rows = [[c['finding_id'][:40], c['old_severity'], c['new_severity'], c['change']]
                          for c in data['severity_changes']]
            lines.append(tabulate(change_rows,
                                 headers=['Finding ID', 'Old', 'New', 'Change'],
                                 tablefmt='simple'))

        return '\n'.join(lines)


def format_mttr_output(mttr_data: Dict, output_format: str) -> str:
    """Format MTTR results for output."""
    if output_format == 'json':
        return json.dumps(mttr_data, indent=2)

    elif output_format == 'csv':
        writer = csv.writer(sys.stdout)
        writer.writerow(['Severity', 'Resolved Count', 'Avg Hours', 'Avg Days', 'Min Hours', 'Max Hours'])
        for sev, metrics in mttr_data.items():
            writer.writerow([sev, metrics['resolved_count'], metrics['avg_hours'],
                           metrics['avg_days'], metrics['min_hours'], metrics['max_hours']])
        return ''

    else:  # table
        if not HAS_TABULATE:
            lines = ["", "=== Mean Time To Resolution (MTTR) ===", ""]
            for sev, metrics in mttr_data.items():
                lines.append(f"{sev.capitalize()}:")
                lines.append(f"  Resolved: {metrics['resolved_count']}")
                lines.append(f"  Avg: {metrics['avg_days']} days ({metrics['avg_hours']} hours)")
            return '\n'.join(lines)

        rows = []
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in mttr_data:
                m = mttr_data[sev]
                rows.append([sev.capitalize(), m['resolved_count'],
                           f"{m['avg_hours']:.1f}", f"{m['avg_days']:.1f}",
                           f"{m['min_hours']:.1f}", f"{m['max_hours']:.1f}"])

        return "\n=== Mean Time To Resolution (MTTR) ===\n\n" + \
               tabulate(rows, headers=['Severity', 'Resolved', 'Avg Hrs', 'Avg Days', 'Min Hrs', 'Max Hrs'],
                       tablefmt='simple')


def main():
    parser = argparse.ArgumentParser(
        description='Compare security scans for drift detection and metrics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare two JSON files (backward compatible)
  python compare_scans.py --baseline baseline.json --current current.json

  # Compare by database scan IDs
  python compare_scans.py --baseline-id abc123 --current-id def456

  # Compare by dates
  python compare_scans.py --baseline-date 2024-01-01 --current-date 2024-01-08

  # Include MTTR calculation
  python compare_scans.py --baseline-id abc123 --current-id def456 --include-mttr

  # Output as JSON
  python compare_scans.py --baseline scan1.json --current scan2.json --output json
        """
    )

    # File-based comparison (backward compatible)
    parser.add_argument('--baseline', help='Baseline scan file path')
    parser.add_argument('--current', help='Current scan file path')

    # Database-based comparison
    parser.add_argument('--baseline-id', help='Baseline scan UUID from database')
    parser.add_argument('--current-id', help='Current scan UUID from database')

    # Date-based comparison
    parser.add_argument('--baseline-date', help='Baseline date (YYYY-MM-DD)')
    parser.add_argument('--current-date', help='Current date (YYYY-MM-DD)')

    # Filters
    parser.add_argument('--tool', help='Filter by tool name (for date comparisons)')
    parser.add_argument('--severity', '-s', help='Filter MTTR by severity')

    # Output options
    parser.add_argument('--output', '-o', choices=['json', 'table', 'csv'],
                       default='table', help='Output format (default: table)')
    parser.add_argument('--include-mttr', action='store_true',
                       help='Include MTTR calculations')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    comparator = ScanComparator()

    try:
        # Determine comparison mode
        if args.baseline and args.current:
            # File-based comparison (backward compatible)
            logger.info(f"Comparing files: {args.baseline} vs {args.current}")
            result = comparator.compare_files(args.baseline, args.current)

        elif args.baseline_id and args.current_id:
            # Database scan ID comparison
            logger.info(f"Comparing scan IDs: {args.baseline_id} vs {args.current_id}")
            result = comparator.compare_by_scan_ids(args.baseline_id, args.current_id)

        elif args.baseline_date and args.current_date:
            # Date-based comparison
            logger.info(f"Comparing dates: {args.baseline_date} vs {args.current_date}")
            result = comparator.compare_by_dates(
                args.baseline_date, args.current_date, args.tool
            )

        else:
            parser.error("Must specify either --baseline/--current, --baseline-id/--current-id, "
                        "or --baseline-date/--current-date")

        # Output comparison results
        print(format_output(result, args.output))

        # Include MTTR if requested
        if args.include_mttr:
            mttr_data = comparator.calculate_mttr(args.severity)
            print(format_mttr_output(mttr_data, args.output))

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        comparator.close_db()


if __name__ == "__main__":
    main()
