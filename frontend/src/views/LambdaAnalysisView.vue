<template>
  <div class="lambda-analysis-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Lambda Code Analysis</h1>
        <p class="subtitle">
          Serverless function security analysis
        </p>
      </div>
      <div class="header-actions">
        <Button
          v-if="!isRunning"
          label="Analyze All"
          icon="pi pi-search"
          :loading="store.loading"
          @click="runAnalysis"
        />
        <Button
          v-else
          label="Stop"
          icon="pi pi-stop"
          severity="danger"
          @click="stopExecution"
        />
      </div>
    </div>

    <!-- Execution Status Panel -->
    <ExecutionProgressPanel
      :execution="store.currentExecution"
      tool-name="Lambda analysis"
      description="Analyzing Lambda functions for security issues, secrets, and vulnerabilities. This scans function code and configurations."
      :logs="executionLogs"
      @dismiss="dismissExecution"
      @view-results="store.fetchAnalyses()"
    />

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_functions }}
        </div>
        <div class="card-label">
          Total Functions
        </div>
      </div>
      <div class="summary-card critical">
        <div class="card-value">
          {{ store.summary.functions_with_secrets }}
        </div>
        <div class="card-label">
          With Secrets
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.functions_with_vulns }}
        </div>
        <div class="card-label">
          With Vulns
        </div>
      </div>
      <div class="summary-card medium">
        <div class="card-value">
          {{ store.summary.high_risk }}
        </div>
        <div class="card-label">
          High Risk
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Dropdown
        v-model="filters.runtime"
        :options="runtimes"
        placeholder="Runtime"
        class="filter-dropdown"
        @change="applyFilters"
      />
      <Dropdown
        v-model="filters.riskLevel"
        :options="riskLevels"
        placeholder="Risk Level"
        class="filter-dropdown"
        @change="applyFilters"
      />
      <Button
        :label="showWithSecretsOnly ? 'Show All' : 'Show With Secrets'"
        :icon="showWithSecretsOnly ? 'pi pi-list' : 'pi pi-key'"
        @click="toggleSecrets"
      />
    </div>

    <DataTable
      :value="store.analyses"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="function_name"
        header="Function"
      />
      <Column
        field="runtime"
        header="Runtime"
      />
      <Column
        field="region"
        header="Region"
      />
      <Column
        field="risk_score"
        header="Risk Score"
      >
        <template #body="{ data }">
          <ProgressBar
            :value="data.risk_score"
            :show-value="true"
            class="risk-bar"
          />
        </template>
      </Column>
      <Column
        field="risk_level"
        header="Risk"
      >
        <template #body="{ data }">
          <Tag
            :severity="getRiskSeverity(data.risk_level)"
            :value="data.risk_level"
          />
        </template>
      </Column>
      <Column header="Issues">
        <template #body="{ data }">
          <span class="issue-badges">
            <Tag
              v-if="data.secrets_found && data.secrets_found.length"
              severity="danger"
              value="Secrets"
            />
            <Tag
              v-if="data.vulnerable_dependencies && data.vulnerable_dependencies.length"
              severity="warning"
              value="Vulns"
            />
          </span>
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            icon="pi pi-eye"
            text
            @click="viewAnalysis(data.id)"
          />
          <Button
            icon="pi pi-download"
            text
            @click="exportAnalysis(data.id)"
          />
        </template>
      </Column>
    </DataTable>

    <Paginator
      v-if="store.pagination.total > store.pagination.pageSize"
      :rows="store.pagination.pageSize"
      :total-records="store.pagination.total"
      :first="(store.pagination.page - 1) * store.pagination.pageSize"
      @page="onPageChange"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useLambdaAnalysisStore } from '../stores/lambdaAnalysis'
import { useExecutionsStore } from '../stores/executions'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import ProgressBar from 'primevue/progressbar'
import Paginator from 'primevue/paginator'
import ExecutionProgressPanel from '../components/executions/ExecutionProgressPanel.vue'

const store = useLambdaAnalysisStore()
const executionsStore = useExecutionsStore()
const showWithSecretsOnly = ref(false)
const executionLogs = ref(null)

const filters = ref({
  runtime: null,
  riskLevel: null,
})

const runtimes = ['python3.11', 'python3.10', 'python3.9', 'nodejs18.x', 'nodejs16.x', 'java17', 'go1.x']
const riskLevels = ['critical', 'high', 'medium', 'low']

const isRunning = computed(() =>
  store.currentExecution?.status === 'running',
)

function getRiskSeverity(level) {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[level] || 'secondary'
}

function applyFilters() {
  store.setFilters(filters.value)
}

function toggleSecrets() {
  showWithSecretsOnly.value = !showWithSecretsOnly.value
  if (showWithSecretsOnly.value) {
    store.fetchWithSecrets()
  } else {
    store.fetchAnalyses()
  }
}

async function viewAnalysis(id) {
  // TODO: Navigate to analysis detail view or show modal
  // For now, fetch is available via store.fetchAnalysis(id)
  await store.fetchAnalysis(id)
}

async function exportAnalysis(id) {
  const result = await store.exportAnalysis(id, 'markdown')
  // Download the exported content
  if (result?.content) {
    const blob = new Blob([result.content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `lambda-analysis-${id}.md`
    a.click()
    URL.revokeObjectURL(url)
  }
}

async function runAnalysis() {
  executionLogs.value = null
  await store.runAnalysis({ analyze_all: true })
}

async function stopExecution() {
  await store.stopCurrentExecution()
}

function dismissExecution() {
  store.currentExecution = null
  executionLogs.value = null
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  if (showWithSecretsOnly.value) {
    store.fetchWithSecrets()
  } else {
    store.fetchAnalyses()
  }
}

onMounted(() => {
  store.fetchAnalyses()
  store.fetchSummary()
})

onUnmounted(() => {
  // Stop any polling when leaving the view
  if (store.currentExecution?.execution_id) {
    executionsStore.stopPolling(store.currentExecution.execution_id)
  }
})
</script>

<style scoped>
.lambda-analysis-view { padding: 1.5rem; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }
.page-header h1 { margin: 0; font-size: 1.75rem; }
.subtitle { color: var(--text-color-secondary); margin-top: 0.25rem; }

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.summary-card {
  padding: 1rem;
  border-radius: 8px;
  background: var(--surface-card);
  border-left: 4px solid;
}
.summary-card.info { border-left-color: var(--blue-500); }
.summary-card.critical { border-left-color: var(--red-500); }
.summary-card.high { border-left-color: var(--orange-500); }
.summary-card.medium { border-left-color: var(--yellow-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
.filter-dropdown { min-width: 150px; }
.risk-bar { height: 8px; }
.issue-badges { display: flex; gap: 0.25rem; }
</style>
