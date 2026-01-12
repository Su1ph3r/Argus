<template>
  <div class="attack-paths-view">
    <!-- Header -->
    <div class="page-header">
      <div class="header-content">
        <h1>Attack Paths</h1>
        <p class="subtitle">
          Discovered attack chains from entry points to targets
        </p>
      </div>
      <div class="header-actions">
        <Button
          label="Analyze"
          icon="pi pi-refresh"
          :loading="store.loading"
          class="analyze-btn"
          @click="runAnalysis"
        />
      </div>
    </div>

    <!-- Summary Cards -->
    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div
        class="summary-card critical clickable"
        :class="{ active: selectedRiskLevel === 'critical' }"
        @click="filterByRisk('critical')"
      >
        <div class="card-value">
          {{ store.summary.critical_paths }}
        </div>
        <div class="card-label">
          Critical Risk
        </div>
        <div class="card-score">
          Score 80-100
        </div>
      </div>
      <div
        class="summary-card high clickable"
        :class="{ active: selectedRiskLevel === 'high' }"
        @click="filterByRisk('high')"
      >
        <div class="card-value">
          {{ store.summary.high_risk_paths }}
        </div>
        <div class="card-label">
          High Risk
        </div>
        <div class="card-score">
          Score 60-79
        </div>
      </div>
      <div
        class="summary-card medium clickable"
        :class="{ active: selectedRiskLevel === 'medium' }"
        @click="filterByRisk('medium')"
      >
        <div class="card-value">
          {{ store.summary.medium_risk_paths }}
        </div>
        <div class="card-label">
          Medium Risk
        </div>
        <div class="card-score">
          Score 40-59
        </div>
      </div>
      <div
        class="summary-card low clickable"
        :class="{ active: selectedRiskLevel === 'low' }"
        @click="filterByRisk('low')"
      >
        <div class="card-value">
          {{ store.summary.low_risk_paths }}
        </div>
        <div class="card-label">
          Low Risk
        </div>
        <div class="card-score">
          Score 0-39
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-section">
      <div class="filter-group">
        <label>Risk Level</label>
        <Dropdown
          v-model="selectedRiskLevel"
          :options="riskScoreOptions"
          option-label="label"
          option-value="value"
          placeholder="Any"
          class="filter-dropdown"
          @change="handleRiskDropdownChange"
        />
      </div>
      <div class="filter-group">
        <label>Exploitability</label>
        <Dropdown
          v-model="localFilters.exploitability"
          :options="exploitabilityOptions"
          option-label="label"
          option-value="value"
          placeholder="Any"
          class="filter-dropdown"
          @change="applyFilters"
        />
      </div>
      <div class="filter-group">
        <label>Entry Point</label>
        <Dropdown
          v-model="localFilters.entryPointType"
          :options="entryPointOptions"
          option-label="label"
          option-value="value"
          placeholder="Any"
          class="filter-dropdown"
          @change="applyFilters"
        />
      </div>
      <div class="filter-group">
        <label>Target</label>
        <Dropdown
          v-model="localFilters.targetType"
          :options="targetOptions"
          option-label="label"
          option-value="value"
          placeholder="Any"
          class="filter-dropdown"
          @change="applyFilters"
        />
      </div>
      <Button
        v-if="store.hasFilters"
        label="Clear"
        icon="pi pi-times"
        severity="secondary"
        text
        @click="clearFilters"
      />
    </div>

    <!-- Loading State -->
    <div
      v-if="store.loading && !store.paths.length"
      class="loading-state"
    >
      <ProgressSpinner />
      <p>Loading attack paths...</p>
    </div>

    <!-- Empty State -->
    <div
      v-else-if="!store.paths.length"
      class="empty-state"
    >
      <i class="pi pi-shield empty-icon" />
      <h3>No Attack Paths Discovered</h3>
      <p>Run the analyzer to discover attack paths from your security findings.</p>
      <Button
        label="Run Analysis"
        icon="pi pi-play"
        @click="runAnalysis"
      />
    </div>

    <!-- Attack Paths List -->
    <div
      v-else
      class="paths-list"
    >
      <AttackPathCard
        v-for="path in store.paths"
        :key="path.id"
        :path="path"
        @view="viewPath"
        @export="exportPath"
      />
    </div>

    <!-- Pagination -->
    <div
      v-if="store.pagination.total > store.pagination.pageSize"
      class="pagination"
    >
      <Paginator
        :rows="store.pagination.pageSize"
        :total-records="store.pagination.total"
        :first="(store.pagination.page - 1) * store.pagination.pageSize"
        @page="onPageChange"
      />
    </div>

    <!-- Detail Dialog -->
    <Dialog
      v-model:visible="showDetail"
      :header="selectedPath?.name"
      :style="{ width: '90vw', maxWidth: '1000px' }"
      modal
      dismissable-mask
    >
      <AttackPathDetail
        v-if="selectedPath"
        :path="selectedPath"
        @export="exportPath"
      />
    </Dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, reactive } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useAttackPathsStore } from '../stores/attackPaths'
import AttackPathCard from '../components/attack-paths/AttackPathCard.vue'
import AttackPathDetail from '../components/attack-paths/AttackPathDetail.vue'

const toast = useToast()
const store = useAttackPathsStore()

const showDetail = ref(false)
const selectedPath = ref(null)

const localFilters = reactive({
  minRiskScore: null,
  maxRiskScore: null,
  exploitability: null,
  entryPointType: null,
  targetType: null,
})

// Track which risk level is selected for highlighting cards
const selectedRiskLevel = ref(null)

// Risk score options with ranges for exact filtering
const riskScoreOptions = [
  { label: 'Any', value: null, min: null, max: null },
  { label: 'Critical (80-100)', value: 'critical', min: 80, max: null },
  { label: 'High (60-79)', value: 'high', min: 60, max: 80 },
  { label: 'Medium (40-59)', value: 'medium', min: 40, max: 60 },
  { label: 'Low (<40)', value: 'low', min: 0, max: 40 },
]

const exploitabilityOptions = [
  { label: 'Any', value: null },
  { label: 'Confirmed', value: 'confirmed' },
  { label: 'Likely', value: 'likely' },
  { label: 'Theoretical', value: 'theoretical' },
]

const entryPointOptions = [
  { label: 'Any', value: null },
  { label: 'Public S3', value: 'public_s3' },
  { label: 'Public Lambda', value: 'public_lambda' },
  { label: 'Public EC2', value: 'public_ec2' },
  { label: 'Public RDS', value: 'public_rds' },
  { label: 'Security Group', value: 'public_security_group' },
  { label: 'Exposed Credentials', value: 'exposed_credentials' },
  { label: 'Weak IAM Policy', value: 'weak_iam_policy' },
]

const targetOptions = [
  { label: 'Any', value: null },
  { label: 'Account Takeover', value: 'account_takeover' },
  { label: 'Data Exfiltration', value: 'data_exfiltration' },
  { label: 'Persistence', value: 'persistence' },
  { label: 'Privilege Escalation', value: 'privilege_escalation' },
  { label: 'Lateral Movement', value: 'lateral_movement' },
]

onMounted(async () => {
  await Promise.all([
    store.fetchPaths(),
    store.fetchSummary(),
  ])
})

const applyFilters = () => {
  // Pass a plain object copy to avoid reactive proxy issues
  store.setFilters({
    minRiskScore: localFilters.minRiskScore,
    maxRiskScore: localFilters.maxRiskScore,
    exploitability: localFilters.exploitability,
    entryPointType: localFilters.entryPointType,
    targetType: localFilters.targetType,
  })
}

// Filter by risk level with exact ranges
// level: 'critical' | 'high' | 'medium' | 'low'
const filterByRisk = (level) => {
  // Toggle filter - if already set to this level, clear it
  if (selectedRiskLevel.value === level) {
    selectedRiskLevel.value = null
    localFilters.minRiskScore = null
    localFilters.maxRiskScore = null
  } else {
    selectedRiskLevel.value = level

    // Set exact ranges for each level
    switch (level) {
    case 'critical':
      localFilters.minRiskScore = 80
      localFilters.maxRiskScore = null // 80-100
      break
    case 'high':
      localFilters.minRiskScore = 60
      localFilters.maxRiskScore = 80 // 60-79
      break
    case 'medium':
      localFilters.minRiskScore = 40
      localFilters.maxRiskScore = 60 // 40-59
      break
    case 'low':
      localFilters.minRiskScore = 0
      localFilters.maxRiskScore = 40 // 0-39
      break
    default:
      localFilters.minRiskScore = null
      localFilters.maxRiskScore = null
    }
  }
  applyFilters()
}

// Handle dropdown selection for risk score
const handleRiskDropdownChange = (event) => {
  const option = event.value
  if (!option) {
    localFilters.minRiskScore = null
    localFilters.maxRiskScore = null
    selectedRiskLevel.value = null
  } else {
    const selected = riskScoreOptions.find(o => o.value === option)
    if (selected) {
      localFilters.minRiskScore = selected.min
      localFilters.maxRiskScore = selected.max
      selectedRiskLevel.value = option
    }
  }
  applyFilters()
}

const clearFilters = () => {
  Object.keys(localFilters).forEach(key => {
    localFilters[key] = null
  })
  selectedRiskLevel.value = null
  store.clearFilters()
}

const onPageChange = (event) => {
  store.setPage(event.page + 1)
}

const runAnalysis = async () => {
  try {
    const result = await store.analyzePaths()
    toast.add({
      severity: 'success',
      summary: 'Analysis Complete',
      detail: `Discovered ${result.paths_discovered} attack paths in ${result.analysis_time_ms}ms`,
      life: 5000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Analysis Failed',
      detail: e.message,
      life: 5000,
    })
  }
}

const viewPath = async (path) => {
  selectedPath.value = await store.fetchPath(path.id)
  showDetail.value = true
}

const exportPath = async (path) => {
  try {
    const result = await store.exportPath(path.id, 'markdown')
    // Copy to clipboard
    await navigator.clipboard.writeText(result.content)
    toast.add({
      severity: 'success',
      summary: 'Exported',
      detail: 'Attack path copied to clipboard as Markdown',
      life: 3000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Export Failed',
      detail: e.message,
      life: 3000,
    })
  }
}
</script>

<style scoped>
.attack-paths-view {
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-xl);
}

.header-content h1 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.header-content .subtitle {
  color: var(--text-secondary);
  font-size: 0.9375rem;
  margin: 0;
}

.analyze-btn {
  background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end));
  border: none;
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
}

.summary-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
  text-align: center;
  transition: all var(--transition-fast);
}

.summary-card.clickable {
  cursor: pointer;
}

.summary-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

.summary-card.active {
  outline: 2px solid var(--accent-primary);
  outline-offset: 2px;
  box-shadow: var(--shadow-glow);
  transform: translateY(-2px);
}

.summary-card.critical.active { border-color: var(--severity-critical); }
.summary-card.high.active { border-color: var(--severity-high); }
.summary-card.medium.active { border-color: var(--severity-medium); }
.summary-card.low.active { border-color: var(--severity-low); }

.summary-card .card-value {
  font-size: 2rem;
  font-weight: 700;
  margin-bottom: var(--spacing-xs);
}

.summary-card .card-label {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--text-primary);
}

.summary-card .card-score {
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

.summary-card.critical {
  border-color: var(--severity-critical-border);
  background: var(--severity-critical-bg);
}
.summary-card.critical .card-value { color: var(--severity-critical); }

.summary-card.high {
  border-color: var(--severity-high-border);
  background: var(--severity-high-bg);
}
.summary-card.high .card-value { color: var(--severity-high); }

.summary-card.medium {
  border-color: var(--severity-medium-border);
  background: var(--severity-medium-bg);
}
.summary-card.medium .card-value { color: var(--severity-medium); }

.summary-card.low {
  border-color: var(--severity-low-border);
  background: var(--severity-low-bg);
}
.summary-card.low .card-value { color: var(--severity-low); }

.filters-section {
  display: flex;
  align-items: flex-end;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
  flex-wrap: wrap;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.filter-group label {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
}

.filter-dropdown {
  min-width: 160px;
}

.loading-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl) * 2;
  text-align: center;
  color: var(--text-secondary);
}

.empty-icon {
  font-size: 4rem;
  color: var(--text-tertiary);
  margin-bottom: var(--spacing-lg);
}

.empty-state h3 {
  color: var(--text-primary);
  margin-bottom: var(--spacing-sm);
}

.paths-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.pagination {
  display: flex;
  justify-content: center;
  margin-top: var(--spacing-xl);
}

@media (max-width: 768px) {
  .summary-cards {
    grid-template-columns: repeat(2, 1fr);
  }

  .page-header {
    flex-direction: column;
    gap: var(--spacing-md);
  }

  .filters-section {
    flex-direction: column;
    align-items: stretch;
  }

  .filter-dropdown {
    width: 100%;
  }
}
</style>
