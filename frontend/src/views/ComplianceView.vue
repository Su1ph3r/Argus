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

    <!-- Summary Cards -->
    <div
      v-if="displayStats"
      class="summary-cards"
    >
      <div class="summary-card">
        <div class="card-icon frameworks">
          <i class="pi pi-th-large" />
        </div>
        <div class="card-content">
          <span class="card-value">{{ displayStats.frameworks_count }}</span>
          <span class="card-label">{{ complianceStore.selectedFramework ? 'Framework' : 'Frameworks' }}</span>
        </div>
      </div>
      <div class="summary-card">
        <div class="card-icon controls">
          <i class="pi pi-check-square" />
        </div>
        <div class="card-content">
          <span class="card-value">{{ displayStats.total_controls }}</span>
          <span class="card-label">Total Controls</span>
        </div>
      </div>
      <div class="summary-card">
        <div class="card-icon passed">
          <i class="pi pi-check-circle" />
        </div>
        <div class="card-content">
          <span class="card-value">{{ displayStats.total_passed }}</span>
          <span class="card-label">Passed</span>
        </div>
      </div>
      <div class="summary-card">
        <div class="card-icon failed">
          <i class="pi pi-times-circle" />
        </div>
        <div class="card-content">
          <span class="card-value">{{ displayStats.total_failed }}</span>
          <span class="card-label">Failed</span>
        </div>
      </div>
      <div class="summary-card wide">
        <div class="card-icon percentage">
          <i class="pi pi-percentage" />
        </div>
        <div class="card-content">
          <span class="card-value">{{ displayStats.overall_pass_percentage }}%</span>
          <span class="card-label">Pass Rate</span>
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

    <!-- Framework Cards Grid (when no framework selected) -->
    <div
      v-if="!complianceStore.selectedFramework && !complianceStore.loading"
      class="frameworks-grid"
    >
      <div
        v-for="fw in complianceStore.frameworks"
        :key="fw.framework"
        class="framework-card"
        @click="selectFramework(fw.framework)"
      >
        <div class="framework-header">
          <span class="framework-name">{{ fw.framework }}</span>
          <Tag
            :severity="getPassRateSeverity(fw.pass_percentage)"
            :value="`${fw.pass_percentage}%`"
          />
        </div>
        <div class="framework-stats">
          <div class="stat">
            <span class="stat-value">{{ fw.controls_checked }}</span>
            <span class="stat-label">Controls</span>
          </div>
          <div class="stat passed">
            <span class="stat-value">{{ fw.controls_passed }}</span>
            <span class="stat-label">Passed</span>
          </div>
          <div class="stat failed">
            <span class="stat-value">{{ fw.controls_failed }}</span>
            <span class="stat-label">Failed</span>
          </div>
        </div>
        <ProgressBar
          :value="fw.pass_percentage"
          :show-value="false"
          class="framework-progress"
        />
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
  color: white;
  margin: 0;
}

.compliance-header .subtitle {
  color: rgba(255, 255, 255, 0.8);
  font-size: 0.875rem;
  margin-top: var(--spacing-xs);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

/* Summary Cards */
.summary-cards {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.summary-card {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: var(--radius-lg);
  padding: var(--spacing-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.summary-card.wide {
  grid-column: span 1;
}

.card-icon {
  width: 48px;
  height: 48px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
}

.card-icon.frameworks {
  background: rgba(99, 102, 241, 0.2);
  color: #6366f1;
}

.card-icon.controls {
  background: rgba(59, 130, 246, 0.2);
  color: #3b82f6;
}

.card-icon.passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.card-icon.failed {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.card-icon.percentage {
  background: rgba(168, 85, 247, 0.2);
  color: #a855f7;
}

.card-content {
  display: flex;
  flex-direction: column;
}

.card-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: white;
}

.card-label {
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.6);
  text-transform: uppercase;
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
  color: white;
  border-radius: var(--radius-md);
  margin-bottom: var(--spacing-lg);
}

/* Framework Cards Grid */
.frameworks-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: var(--spacing-md);
}

.framework-card {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: all 0.2s ease;
}

.framework-card:hover {
  border-color: var(--primary-color);
  transform: translateY(-2px);
}

.framework-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.framework-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: white;
}

.framework-stats {
  display: flex;
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-md);
}

.stat {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.stat-value {
  font-size: 1.25rem;
  font-weight: 600;
  color: white;
}

.stat-label {
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.6);
}

.stat.passed .stat-value {
  color: #22c55e;
}

.stat.failed .stat-value {
  color: #ef4444;
}

.framework-progress {
  height: 6px;
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
  color: white;
  margin: 0;
}

.controls-table {
  background: var(--card-bg);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.control-title-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.control-title {
  color: white;
}

.control-requirement {
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.6);
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
  color: rgba(255, 255, 255, 0.6);
}

/* Responsive */
@media (max-width: 1200px) {
  .summary-cards {
    grid-template-columns: repeat(3, 1fr);
  }

  .summary-card.wide {
    grid-column: span 1;
  }
}

@media (max-width: 768px) {
  .compliance-header {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-md);
  }

  .summary-cards {
    grid-template-columns: repeat(2, 1fr);
  }

  .frameworks-grid {
    grid-template-columns: 1fr;
  }
}
</style>
