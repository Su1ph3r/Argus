<template>
  <div class="compliance-view">
    <div class="compliance-header">
      <div class="header-content">
        <h2>Compliance Dashboard</h2>
        <p class="subtitle">
          {{ complianceStore.summary?.frameworks_count || 0 }} frameworks
          <span v-if="complianceStore.selectedFramework">({{ complianceStore.selectedFramework }})</span>
        </p>
      </div>
      <div class="header-actions">
        <Button
          label="Export CSV"
          icon="pi pi-download"
          severity="secondary"
          @click="exportCsv"
        />
        <Button
          label="Export PDF"
          icon="pi pi-file-pdf"
          severity="secondary"
          @click="exportPdf"
        />
      </div>
    </div>

    <!-- Summary Strip -->
    <div
      v-if="displayStats"
      class="summary-strip"
    >
      <div class="summary-stat">
        <div class="stat-icon frameworks">
          <i class="pi pi-th-large" />
        </div>
        <div class="stat-content">
          <span class="stat-value">{{ displayStats.frameworks_count }}</span>
          <span class="stat-label">{{ complianceStore.selectedFramework ? 'Framework' : 'Frameworks' }}</span>
        </div>
      </div>
      <div class="stat-divider" />
      <div class="summary-stat">
        <div class="stat-icon controls">
          <i class="pi pi-check-square" />
        </div>
        <div class="stat-content">
          <span class="stat-value">{{ displayStats.total_controls }}</span>
          <span class="stat-label">Controls</span>
        </div>
      </div>
      <div class="stat-divider" />
      <div class="summary-stat">
        <div class="stat-icon passed">
          <i class="pi pi-check-circle" />
        </div>
        <div class="stat-content">
          <span class="stat-value">{{ displayStats.total_passed }}</span>
          <span class="stat-label">Passed</span>
        </div>
      </div>
      <div class="stat-divider" />
      <div class="summary-stat">
        <div class="stat-icon failed">
          <i class="pi pi-times-circle" />
        </div>
        <div class="stat-content">
          <span class="stat-value">{{ displayStats.total_failed }}</span>
          <span class="stat-label">Failed</span>
        </div>
      </div>
      <div class="stat-divider" />
      <div class="summary-stat">
        <div class="stat-icon percentage">
          <i class="pi pi-percentage" />
        </div>
        <div class="stat-content">
          <span class="stat-value">{{ displayStats.overall_pass_percentage }}%</span>
          <span class="stat-label">Pass Rate</span>
        </div>
      </div>
    </div>

    <!-- Framework Filter -->
    <div class="filters-section">
      <Dropdown
        v-model="selectedFrameworkFilter"
        :options="complianceStore.frameworkOptions"
        option-label="label"
        option-value="value"
        placeholder="All Frameworks"
        show-clear
        class="framework-dropdown"
        @change="handleFrameworkChange"
      />
    </div>

    <!-- Error Message -->
    <div
      v-if="complianceStore.error"
      class="error-message"
    >
      <i class="pi pi-exclamation-triangle" />
      {{ complianceStore.error }}
      <Button
        label="Retry"
        size="small"
        @click="loadData"
      />
    </div>

    <!-- Framework List (when no framework selected) -->
    <div
      v-if="!complianceStore.selectedFramework && !complianceStore.loading"
      class="frameworks-list"
    >
      <div
        v-for="fw in complianceStore.frameworks"
        :key="fw.framework"
        class="framework-row"
        @click="selectFramework(fw.framework)"
      >
        <div class="framework-info">
          <span class="framework-name">{{ fw.framework }}</span>
        </div>
        <div class="framework-metrics">
          <div class="metric">
            <span class="metric-value">{{ fw.controls_checked }}</span>
            <span class="metric-label">Controls</span>
          </div>
          <div class="metric passed">
            <span class="metric-value">{{ fw.controls_passed }}</span>
            <span class="metric-label">Passed</span>
          </div>
          <div class="metric failed">
            <span class="metric-value">{{ fw.controls_failed }}</span>
            <span class="metric-label">Failed</span>
          </div>
        </div>
        <div class="framework-progress-wrapper">
          <ProgressBar
            :value="fw.pass_percentage"
            :show-value="false"
            class="framework-progress"
          />
          <Tag
            :severity="getPassRateSeverity(fw.pass_percentage)"
            :value="`${fw.pass_percentage}%`"
            class="pass-tag"
          />
        </div>
        <div class="framework-arrow">
          <i class="pi pi-chevron-right" />
        </div>
      </div>
    </div>

    <!-- Control Details Table (when framework selected) -->
    <div
      v-if="complianceStore.selectedFramework"
      class="controls-section"
    >
      <div class="controls-header">
        <Button
          icon="pi pi-arrow-left"
          label="Back to Frameworks"
          severity="secondary"
          text
          @click="clearSelection"
        />
        <h3>{{ complianceStore.selectedFramework }} Controls</h3>
      </div>

      <DataTable
        :value="complianceStore.controls"
        :loading="complianceStore.loading"
        striped-rows
        paginator
        :rows="20"
        :rows-per-page-options="[10, 20, 50, 100]"
        class="controls-table"
        :row-class="() => 'clickable-row'"
        @row-click="handleControlClick"
      >
        <Column
          field="control_id"
          header="Control ID"
          sortable
          style="width: 120px"
        />
        <Column
          field="control_title"
          header="Title"
          sortable
        >
          <template #body="{ data }">
            <div class="control-title-cell">
              <span class="control-title">{{ data.control_title || '-' }}</span>
              <span
                v-if="data.requirement"
                class="control-requirement"
              >{{ data.requirement }}</span>
            </div>
          </template>
        </Column>
        <Column
          field="severity"
          header="Severity"
          sortable
          style="width: 100px"
        >
          <template #body="{ data }">
            <Tag
              v-if="data.severity"
              :severity="getSeverityColor(data.severity)"
              :value="data.severity"
            />
            <span v-else>-</span>
          </template>
        </Column>
        <Column
          field="status"
          header="Status"
          sortable
          style="width: 100px"
        >
          <template #body="{ data }">
            <Tag
              :severity="data.status === 'pass' ? 'success' : 'danger'"
              :value="data.status.toUpperCase()"
            />
          </template>
        </Column>
        <Column
          field="finding_count"
          header="Findings"
          sortable
          style="width: 100px"
        >
          <template #body="{ data }">
            <span :class="{ 'has-findings': data.finding_count > 0 }">
              {{ data.finding_count }}
            </span>
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- Loading State -->
    <div
      v-if="complianceStore.loading && !complianceStore.frameworks.length"
      class="loading-state"
    >
      <ProgressSpinner />
      <p>Loading compliance data...</p>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useComplianceStore } from '../stores/compliance'
import { jsPDF } from 'jspdf'
import autoTable from 'jspdf-autotable'
import api from '../services/api'

const router = useRouter()
const complianceStore = useComplianceStore()
const selectedFrameworkFilter = ref(null)

// Computed stats for selected framework or overall summary
const displayStats = computed(() => {
  if (complianceStore.selectedFramework) {
    // Find the framework data for the selected framework
    const fw = complianceStore.frameworks.find(
      f => f.framework === complianceStore.selectedFramework,
    )
    if (fw) {
      return {
        frameworks_count: 1,
        total_controls: fw.controls_checked,
        total_passed: fw.controls_passed,
        total_failed: fw.controls_failed,
        overall_pass_percentage: fw.pass_percentage,
      }
    }
  }
  return complianceStore.summary
})

const loadData = async () => {
  await complianceStore.fetchSummary()
}

const handleFrameworkChange = (event) => {
  complianceStore.selectFramework(event.value)
}

const selectFramework = (framework) => {
  selectedFrameworkFilter.value = framework
  complianceStore.selectFramework(framework)
}

const clearSelection = () => {
  selectedFrameworkFilter.value = null
  complianceStore.clearSelection()
}

const getPassRateSeverity = (percentage) => {
  if (percentage >= 90) return 'success'
  if (percentage >= 70) return 'warn'
  return 'danger'
}

const getSeverityColor = (severity) => {
  const colors = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'info',
    info: 'secondary',
  }
  return colors[severity?.toLowerCase()] || 'secondary'
}

// Handle control row click to navigate to control detail view
const handleControlClick = (event) => {
  const control = event.data
  if (control?.control_id && complianceStore.selectedFramework) {
    router.push(`/compliance/${encodeURIComponent(complianceStore.selectedFramework)}/${encodeURIComponent(control.control_id)}`)
  }
}

const exportCsv = () => {
  const url = api.getComplianceExportUrl(complianceStore.selectedFramework)
  window.open(url, '_blank')
}

const exportPdf = () => {
  const doc = new jsPDF()
  const framework = complianceStore.selectedFramework || 'All Frameworks'

  // Title
  doc.setFontSize(18)
  doc.text(`Compliance Report - ${framework}`, 14, 20)

  // Summary
  if (complianceStore.summary) {
    doc.setFontSize(12)
    doc.text(`Overall Pass Rate: ${complianceStore.summary.overall_pass_percentage}%`, 14, 32)
    doc.text(`Total Controls: ${complianceStore.summary.total_controls}`, 14, 40)
    doc.text(`Passed: ${complianceStore.summary.total_passed} | Failed: ${complianceStore.summary.total_failed}`, 14, 48)
  }

  // Table data
  let tableData = []
  const startY = 58

  if (complianceStore.selectedFramework && complianceStore.controls.length) {
    // Control-level data
    tableData = complianceStore.controls.map(c => [
      c.control_id,
      c.control_title || '-',
      c.severity || '-',
      c.status.toUpperCase(),
      c.finding_count,
    ])
    autoTable(doc, {
      head: [['Control ID', 'Title', 'Severity', 'Status', 'Findings']],
      body: tableData,
      startY: startY,
      styles: { fontSize: 8 },
      headStyles: { fillColor: [99, 102, 241] },
    })
  } else {
    // Framework-level data
    tableData = complianceStore.frameworks.map(f => [
      f.framework,
      f.controls_checked,
      f.controls_passed,
      f.controls_failed,
      `${f.pass_percentage}%`,
    ])
    autoTable(doc, {
      head: [['Framework', 'Controls', 'Passed', 'Failed', 'Pass Rate']],
      body: tableData,
      startY: startY,
      styles: { fontSize: 10 },
      headStyles: { fillColor: [99, 102, 241] },
    })
  }

  doc.save(`compliance-${framework.replace(/\s+/g, '-').toLowerCase()}.pdf`)
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.compliance-view {
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  min-height: calc(100vh - 180px);
}

.compliance-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--spacing-lg);
}

.compliance-header h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-primary);
  margin: 0;
}

.compliance-header .subtitle {
  color: var(--text-secondary);
  font-size: 0.875rem;
  margin-top: var(--spacing-xs);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

/* Summary Strip - Horizontal Layout */
.summary-strip {
  display: flex;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-md) var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
  gap: var(--spacing-lg);
  flex-wrap: wrap;
}

.summary-stat {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  flex: 1;
  min-width: 120px;
}

.stat-divider {
  width: 1px;
  height: 40px;
  background: var(--border-color);
}

.stat-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
  flex-shrink: 0;
}

.stat-icon.frameworks {
  background: rgba(99, 102, 241, 0.2);
  color: #6366f1;
}

.stat-icon.controls {
  background: rgba(59, 130, 246, 0.2);
  color: #3b82f6;
}

.stat-icon.passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.stat-icon.failed {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.stat-icon.percentage {
  background: rgba(168, 85, 247, 0.2);
  color: #a855f7;
}

.stat-content {
  display: flex;
  flex-direction: column;
}

.stat-value {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.2;
}

.stat-label {
  font-size: 0.7rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.025em;
}

/* Filters */
.filters-section {
  margin-bottom: var(--spacing-lg);
}

.framework-dropdown {
  min-width: 250px;
}

/* Fix dropdown clear button positioning */
.framework-dropdown :deep(.p-dropdown-clear-icon) {
  position: relative;
  right: auto;
  margin-left: var(--spacing-sm);
}

/* Error */
.error-message {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: rgba(231, 76, 60, 0.2);
  color: var(--text-primary);
  border-radius: var(--radius-md);
  margin-bottom: var(--spacing-lg);
}

/* Framework List - Horizontal Rows */
.frameworks-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.framework-row {
  display: flex;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-md) var(--spacing-lg);
  cursor: pointer;
  transition: all 0.2s ease;
  gap: var(--spacing-lg);
}

.framework-row:hover {
  border-color: var(--primary-color);
  transform: translateX(4px);
}

.framework-row:hover .framework-arrow {
  opacity: 1;
  transform: translateX(4px);
}

.framework-info {
  flex: 0 0 280px;
  min-width: 0;
}

.framework-name {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.framework-metrics {
  display: flex;
  gap: var(--spacing-xl);
  flex-shrink: 0;
}

.metric {
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 60px;
}

.metric-value {
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--text-primary);
}

.metric-label {
  font-size: 0.7rem;
  color: var(--text-secondary);
  text-transform: uppercase;
}

.metric.passed .metric-value {
  color: #22c55e;
}

.metric.failed .metric-value {
  color: #ef4444;
}

.framework-progress-wrapper {
  flex: 1;
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  min-width: 150px;
}

.framework-progress {
  flex: 1;
  height: 8px;
}

.pass-tag {
  flex-shrink: 0;
  min-width: 50px;
  text-align: center;
}

.framework-arrow {
  flex-shrink: 0;
  width: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0.3;
  color: var(--text-tertiary);
  transition: all 0.2s ease;
}

/* Controls Section */
.controls-section {
  flex: 1;
}

.controls-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
}

.controls-header h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
}

.controls-table {
  background: var(--bg-card);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.control-title-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.control-title {
  color: var(--text-primary);
}

.control-requirement {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.has-findings {
  color: #ef4444;
  font-weight: 600;
}

/* Clickable rows */
.controls-table :deep(.clickable-row) {
  cursor: pointer;
}

.controls-table :deep(.clickable-row:hover) {
  background: rgba(99, 102, 241, 0.1) !important;
}

/* Loading State */
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  color: var(--text-secondary);
}

/* Responsive - Tablet */
@media (max-width: 1024px) {
  .framework-info {
    flex: 0 0 200px;
  }

  .framework-metrics {
    gap: var(--spacing-md);
  }

  .metric {
    min-width: 50px;
  }
}

/* Responsive - Mobile */
@media (max-width: 768px) {
  .compliance-header {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-md);
  }

  .summary-strip {
    flex-direction: column;
    align-items: stretch;
    gap: var(--spacing-md);
    padding: var(--spacing-md);
  }

  .summary-stat {
    justify-content: flex-start;
  }

  .stat-divider {
    display: none;
  }

  .framework-row {
    flex-direction: column;
    align-items: stretch;
    gap: var(--spacing-md);
    padding: var(--spacing-md);
  }

  .framework-row:hover {
    transform: translateX(0);
    transform: translateY(-2px);
  }

  .framework-info {
    flex: none;
    width: 100%;
  }

  .framework-metrics {
    justify-content: space-around;
    width: 100%;
  }

  .framework-progress-wrapper {
    width: 100%;
  }

  .framework-arrow {
    display: none;
  }
}
</style>
