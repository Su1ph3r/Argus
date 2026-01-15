# Web Frontend

Nubicustos includes a modern Vue.js 3 web interface providing 22+ specialized views for security findings, attack paths, compliance status, and more.

## Overview

The frontend is built with:
- **Vue 3** with Composition API
- **Vue Router** for navigation
- **Pinia** for state management
- **PrimeVue** UI components
- **Chart.js** for visualizations
- **jsPDF** for report generation

Access the frontend at `http://localhost:8080` after starting the stack.

## Available Views

### Dashboard
**Path**: `/dashboard`

Security posture overview with:
- Critical/high/medium/low finding counts
- Severity distribution chart
- Recent scans timeline
- Attack path summary
- Compliance status overview

### Findings
**Path**: `/findings`

Comprehensive finding management:
- Searchable data table with pagination
- Filter by severity, provider, tool, status
- Sort by any column
- Bulk status updates
- Export to CSV/JSON/PDF
- Quick view with finding details

### Finding Detail
**Path**: `/findings/:id`

Full finding information:
- Complete finding details
- Affected resource information
- Remediation guidance
- Related attack paths
- Status history
- AWS CLI verification commands

### Attack Paths
**Path**: `/attack-paths`

Attack chain visualization:
- List of discovered paths with risk scores
- Interactive graph visualization
- Node details on click
- MITRE ATT&CK mapping
- PoC commands with copy button
- Filter by severity and impact

### Compliance
**Path**: `/compliance`

Framework compliance tracking:
- CIS, SOC2, PCI-DSS status
- Pass/fail/unknown counts
- Control-level details
- Gap analysis
- Export compliance reports

### Compliance Detail (v1.0.2)
**Path**: `/compliance/:framework`

Framework-specific breakdown:
- Individual control status
- Evidence for each control
- Remediation guidance
- Historical compliance trends
- Export framework report

### Scans
**Path**: `/scans`

Scan management:
- Scan history with status
- Active scan monitoring
- Trigger new scans
- Profile selection
- Cancel running scans
- View scan details
- **Bulk Operations (v1.0.2)**:
  - Multi-select scans with checkboxes
  - Bulk delete selected scans
  - Bulk archive to downloadable ZIP
  - Confirmation dialogs for destructive actions

### Scan Detail
**Path**: `/scans/:id`

Individual scan results:
- Tool execution status
- Finding counts by severity
- Duration and timestamps
- **Per-Tool Error Dialog (v1.0.2)**: Shows which tools failed and why
- Error breakdown by tool
- Rerun option

### Public Exposures
**Path**: `/public-exposures`

Attack surface monitoring:
- Publicly accessible resources
- Internet-facing services
- Open security groups
- Public S3 buckets
- Risk assessment

### Exposed Credentials
**Path**: `/exposed-credentials`

Credential leak detection:
- Leaked credentials list
- Source of exposure
- Affected services
- Remediation urgency
- Credential rotation guidance

### Privilege Escalation
**Path**: `/privesc-paths`

IAM lateral movement analysis:
- Privilege escalation paths
- Role assumption chains
- Permission boundaries
- Policy analysis
- Risk scoring

### IMDS Checks
**Path**: `/imds-checks`

EC2 metadata vulnerabilities:
- IMDSv1 vs IMDSv2 status
- Instance role exposure risk
- Credential theft vectors
- Remediation commands

### Lambda Analysis
**Path**: `/lambda-analysis`

Serverless security:
- Function inventory
- Overprivileged roles
- Environment variable secrets
- VPC configuration
- Runtime vulnerabilities

### CloudFox
**Path**: `/cloudfox`

AWS enumeration results:
- Attack surface analysis
- Privilege escalation findings
- Resource inventory
- Permission mappings
- Export options

### Pacu
**Path**: `/pacu`

AWS exploitation framework:
- Module execution history
- Findings from Pacu modules
- Credential discoveries
- Attack surface insights

### Enumerate IAM
**Path**: `/enumerate-iam`

IAM permission mapping:
- User/role permissions
- Policy analysis
- Effective permissions
- Cross-account access
- Service-linked roles

### Assumed Roles
**Path**: `/assumed-roles`

Cross-account analysis:
- Role trust relationships
- Assumption patterns
- External account access
- Permission inheritance

### Credentials
**Path**: `/credentials`

Credential validation:
- Cloud provider status
- Permission verification
- Credential health
- Expiration warnings

### Severity Overrides
**Path**: `/severity-overrides`

Custom severity adjustments:
- Override finding severity
- Business context rules
- False positive handling
- Bulk updates

### Settings
**Path**: `/settings`

Configuration management:
- API settings
- Notification preferences
- User preferences
- Theme selection

## Navigation

The sidebar provides quick access to all views:

```
├── Dashboard
├── Findings
│   ├── All Findings
│   └── Severity Overrides
├── Attack Paths
│   ├── Attack Paths
│   └── Privilege Escalation
├── Compliance
├── Scans
├── AWS Security
│   ├── Public Exposures
│   ├── Exposed Credentials
│   ├── IMDS Checks
│   ├── Lambda Analysis
│   ├── CloudFox
│   ├── Pacu
│   ├── Enumerate IAM
│   └── Assumed Roles
├── Credentials
└── Settings
```

## Components

### Layout Components
- `AppSidebar.vue` - Navigation sidebar
- `AppHeader.vue` - Top header with search
- `AppFooter.vue` - Footer with version info

### Dashboard Components
- `MetricsCard.vue` - Summary statistics
- `SeverityChart.vue` - Pie/bar charts
- `RecentScans.vue` - Scan timeline
- `AttackPathSummary.vue` - Critical paths

### Finding Components
- `FindingsTable.vue` - Data table with filters
- `FindingCard.vue` - Finding detail card
- `SeverityBadge.vue` - Severity indicator
- `RemediationPanel.vue` - Fix guidance

### Attack Path Components
- `AttackPathGraph.vue` - D3.js visualization
- `PathNodeDetail.vue` - Node information
- `MitreMapping.vue` - ATT&CK display
- `PocCommandList.vue` - Verification steps

## State Management

Pinia stores manage application state:

```javascript
// stores/findings.js
export const useFindingsStore = defineStore('findings', {
  state: () => ({
    findings: [],
    loading: false,
    filters: { severity: [], provider: [] }
  }),
  actions: {
    async fetchFindings(params) { ... },
    async updateStatus(id, status) { ... }
  }
})
```

Available stores:
- `findings` - Finding data and filters
- `scans` - Scan management, bulk operations, archives (v1.0.2)
- `attackPaths` - Attack path data
- `compliance` - Compliance status
- `assumedRoles` - Role assumption analysis (v1.0.2)
- `toast` - Centralized notifications (v1.0.2)
- `settings` - User preferences

## API Integration

Services communicate with the REST API:

```javascript
// services/api.js
import axios from 'axios'

const api = axios.create({
  baseURL: '/api'
})

export const findingsApi = {
  list: (params) => api.get('/findings', { params }),
  get: (id) => api.get(`/findings/${id}`),
  update: (id, data) => api.patch(`/findings/${id}`, data)
}
```

## Development

### Running Locally
```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` in development mode.

### Building for Production
```bash
npm run build
```

Output in `frontend/dist/`, served by Nginx.

### Code Style
```bash
npm run lint      # ESLint
npm run format    # Prettier
```

## Customization

### Theme
Edit `src/assets/theme.css` for color customization.

### Adding Views
1. Create component in `src/views/`
2. Add route in `src/router/index.js`
3. Add navigation in `AppSidebar.vue`

### Adding Components
1. Create in `src/components/`
2. Import where needed
3. Follow PrimeVue patterns

---

*See also: [[REST API Overview|API]], [[System Architecture|ARCHITECTURE]]*
