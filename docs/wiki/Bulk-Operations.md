# Bulk Operations

> Added in v1.0.2

Nubicustos provides bulk operations for managing multiple scans at once, including multi-select, bulk delete, and archive functionality.

## Overview

Bulk operations allow you to:
- Select multiple scans using checkboxes
- Delete multiple scans in a single action
- Create downloadable ZIP archives of scan reports
- Manage archives (list, download, delete)

## Web UI Usage

### Multi-Select Scans

1. Navigate to **Scans** page (`/scans`)
2. Use checkboxes in the leftmost column to select scans
3. A bulk actions toolbar appears when scans are selected
4. Available actions:
   - **Delete Selected** - Remove selected scans and their data
   - **Archive Selected** - Create a ZIP file of selected scan reports

### Bulk Delete

1. Select one or more scans
2. Click **Delete Selected** in the toolbar
3. Confirm in the dialog
4. Scans and associated data are permanently removed

### Bulk Archive

1. Select scans you want to archive
2. Click **Archive Selected** in the toolbar
3. System creates a ZIP file containing:
   - JSON reports from each scan
   - HTML reports (if available)
   - CSV exports
4. Download link appears when ready

## API Usage

### Delete Multiple Scans

```bash
curl -X DELETE http://localhost:8000/api/scans/bulk \
  -H "Content-Type: application/json" \
  -d '{"scan_ids": ["scan-id-1", "scan-id-2", "scan-id-3"]}'
```

**Response:**
```json
{
  "deleted": 3,
  "failed": [],
  "message": "Successfully deleted 3 scans"
}
```

### Create Archive

```bash
curl -X POST http://localhost:8000/api/scans/bulk/archive \
  -H "Content-Type: application/json" \
  -d '{"scan_ids": ["scan-id-1", "scan-id-2"]}'
```

**Response:**
```json
{
  "archive_id": "archive-uuid",
  "filename": "scans_2024-01-15_143022.zip",
  "size_bytes": 1048576,
  "download_url": "/api/scans/archives/archive-uuid/download"
}
```

### List Archives

```bash
curl http://localhost:8000/api/scans/archives
```

**Response:**
```json
{
  "archives": [
    {
      "id": "archive-uuid",
      "filename": "scans_2024-01-15_143022.zip",
      "created_at": "2024-01-15T14:30:22Z",
      "size_bytes": 1048576,
      "scan_count": 2
    }
  ]
}
```

### Download Archive

```bash
curl -O http://localhost:8000/api/scans/archives/{archive_id}/download
```

### Delete Archive

```bash
curl -X DELETE http://localhost:8000/api/scans/archives/{archive_id}
```

## Archive Contents

Each archive ZIP contains:

```
scans_2024-01-15_143022.zip
├── scan-id-1/
│   ├── prowler-report.json
│   ├── scoutsuite-report.json
│   ├── findings.csv
│   └── metadata.json
├── scan-id-2/
│   ├── prowler-report.json
│   ├── findings.csv
│   └── metadata.json
└── archive-manifest.json
```

The `archive-manifest.json` contains:
- Archive creation timestamp
- List of included scans
- Total finding counts
- Tool execution summary

## Database Schema

Bulk operations use the `scan_files` table to track report files:

```sql
CREATE TABLE scan_files (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    filename VARCHAR(255),
    file_path VARCHAR(1024),
    file_type VARCHAR(50),
    size_bytes INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## Security Considerations

- Archive creation validates file paths to prevent path traversal
- Zip slip prevention ensures safe archive extraction
- Delete operations are permanent and cannot be undone
- Archives are stored in `/reports/archives/` directory

## Use Cases

### Cleanup Old Scans
```bash
# Get scans older than 30 days
OLD_SCANS=$(curl -s "http://localhost:8000/api/scans?older_than=30d" | jq -r '.scans[].id')

# Delete them
curl -X DELETE http://localhost:8000/api/scans/bulk \
  -H "Content-Type: application/json" \
  -d "{\"scan_ids\": $OLD_SCANS}"
```

### Export for Compliance Audit
```bash
# Archive all compliance scans
COMPLIANCE_SCANS=$(curl -s "http://localhost:8000/api/scans?profile=compliance-only" | jq -r '.scans[].id')

curl -X POST http://localhost:8000/api/scans/bulk/archive \
  -H "Content-Type: application/json" \
  -d "{\"scan_ids\": $COMPLIANCE_SCANS}"
```

---

*See also: [[REST API Overview|API]], [[Web Frontend|Web-Frontend]], [[Scans|Scan-Orchestration]]*
