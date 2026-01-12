<template>
  <div class="imds-checks-view">
    <div class="page-header">
      <div class="header-content">
        <h1>IMDS/Metadata Checks</h1>
        <p class="subtitle">
          Instance metadata service vulnerability checks
        </p>
      </div>
      <div class="header-actions">
        <Button
          v-if="!isRunning"
          label="Run Scan"
          icon="pi pi-play"
          :loading="store.loading"
          @click="runScan"
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
    <div
      v-if="store.currentExecution"
      class="execution-panel"
      :class="executionStatusClass"
    >
      <div class="execution-header">
        <div class="execution-info">
          <i
            :class="executionIcon"
            class="execution-icon"
          />
          <span class="execution-title">{{ executionTitle }}</span>
        </div>
        <div class="execution-meta">
          <span
            v-if="store.currentExecution.execution_id"
            class="execution-id"
          >
            ID: {{ store.currentExecution.execution_id }}
          </span>
        </div>
      </div>
      <div
        v-if="store.currentExecution.error"
        class="execution-error"
      >
        {{ store.currentExecution.error }}
      </div>
      <div
        v-if="executionLogs"
        class="execution-logs"
      >
        <pre>{{ executionLogs }}</pre>
      </div>
      <div
        v-if="!isRunning"
        class="execution-actions"
      >
        <Button
          label="Dismiss"
          text
          size="small"
          @click="dismissExecution"
        />
        <Button
          v-if="store.currentExecution.status === 'completed'"
          label="View Results"
          size="small"
          @click="store.fetchChecks()"
        />
      </div>
    </div>

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_instances }}
        </div>
        <div class="card-label">
          Total Instances
        </div>
      </div>
      <div class="summary-card critical">
        <div class="card-value">
          {{ store.summary.imds_v1_enabled }}
        </div>
        <div class="card-label">
          IMDSv1 Enabled
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.ssrf_vulnerable }}
        </div>
        <div class="card-label">
          SSRF Vulnerable
        </div>
      </div>
      <div class="summary-card medium">
        <div class="card-value">
          {{ store.summary.container_exposed }}
        </div>
        <div class="card-label">
          Container Exposed
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Button
        :label="showVulnerableOnly ? 'Show All' : 'Show Vulnerable'"
        :icon="showVulnerableOnly ? 'pi pi-list' : 'pi pi-exclamation-triangle'"
        @click="toggleVulnerable"
      />
    </div>

    <DataTable
      :value="store.checks"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="instance_id"
        header="Instance ID"
      />
      <Column
        field="instance_name"
        header="Name"
      />
      <Column
        field="region"
        header="Region"
      />
      <Column
        field="imds_v1_enabled"
        header="IMDSv1"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.imds_v1_enabled ? 'danger' : 'success'"
            :value="data.imds_v1_enabled ? 'Enabled' : 'Disabled'"
          />
        </template>
      </Column>
      <Column
        field="http_tokens_required"
        header="Tokens Required"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.http_tokens_required ? 'success' : 'warning'"
            :value="data.http_tokens_required ? 'Yes' : 'No'"
          />
        </template>
      </Column>
      <Column
        field="ssrf_vulnerable"
        header="SSRF"
      >
        <template #body="{ data }">
          <i :class="data.ssrf_vulnerable ? 'pi pi-exclamation-triangle text-danger' : 'pi pi-check text-success'" />
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
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useImdsChecksStore } from '../stores/imdsChecks'
import { useExecutionsStore } from '../stores/executions'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Paginator from 'primevue/paginator'

const store = useImdsChecksStore()
const executionsStore = useExecutionsStore()
const toast = useToast()
const showVulnerableOnly = ref(false)
const executionLogs = ref(null)

const isRunning = computed(() =>
  store.currentExecution?.status === 'running',
)

const executionStatusClass = computed(() => {
  const status = store.currentExecution?.status
  return {
    'status-running': status === 'running',
    'status-completed': status === 'completed',
    'status-failed': status === 'failed',
    'status-pending': status === 'pending',
  }
})

const executionIcon = computed(() => {
  const status = store.currentExecution?.status
  const icons = {
    running: 'pi pi-spin pi-spinner',
    completed: 'pi pi-check-circle',
    failed: 'pi pi-times-circle',
    pending: 'pi pi-clock',
  }
  return icons[status] || 'pi pi-info-circle'
})

const executionTitle = computed(() => {
  const status = store.currentExecution?.status
  const titles = {
    running: 'IMDS scan running...',
    completed: 'IMDS scan completed',
    failed: 'IMDS scan failed',
    pending: 'IMDS scan pending',
  }
  return titles[status] || 'IMDS scan'
})

function getRiskSeverity(level) {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[level] || 'secondary'
}

function toggleVulnerable() {
  showVulnerableOnly.value = !showVulnerableOnly.value
  if (showVulnerableOnly.value) {
    store.fetchVulnerable()
  } else {
    store.fetchChecks()
  }
}

async function runScan() {
  executionLogs.value = null
  try {
    await store.runScan({})
    toast.add({
      severity: 'info',
      summary: 'Scan Started',
      detail: 'IMDS vulnerability scan is now running',
      life: 3000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Scan Failed',
      detail: e.message || 'Failed to start IMDS scan',
      life: 5000,
    })
  }
}

async function stopExecution() {
  await store.stopCurrentExecution()
  toast.add({
    severity: 'warn',
    summary: 'Scan Stopped',
    detail: 'IMDS scan was cancelled',
    life: 3000,
  })
}

// Watch for execution status changes to show completion notifications
watch(
  () => store.currentExecution?.status,
  (newStatus, oldStatus) => {
    if (oldStatus === 'running' && newStatus === 'completed') {
      toast.add({
        severity: 'success',
        summary: 'Scan Completed',
        detail: 'IMDS vulnerability scan finished successfully',
        life: 4000,
      })
    } else if (oldStatus === 'running' && newStatus === 'failed') {
      toast.add({
        severity: 'error',
        summary: 'Scan Failed',
        detail: store.currentExecution?.error || 'IMDS scan encountered an error',
        life: 5000,
      })
    }
  },
)

function dismissExecution() {
  store.currentExecution = null
  executionLogs.value = null
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  if (showVulnerableOnly.value) {
    store.fetchVulnerable()
  } else {
    store.fetchChecks()
  }
}

onMounted(() => {
  store.fetchChecks()
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
.imds-checks-view { padding: 1.5rem; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }
.page-header h1 { margin: 0; font-size: 1.75rem; }
.subtitle { color: var(--text-color-secondary); margin-top: 0.25rem; }

.execution-panel {
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 1.5rem;
  background: var(--surface-card);
  border-left: 4px solid var(--blue-500);
}
.execution-panel.status-running { border-left-color: var(--blue-500); background: rgba(59, 130, 246, 0.1); }
.execution-panel.status-completed { border-left-color: var(--green-500); background: rgba(34, 197, 94, 0.1); }
.execution-panel.status-failed { border-left-color: var(--red-500); background: rgba(239, 68, 68, 0.1); }
.execution-panel.status-pending { border-left-color: var(--yellow-500); background: rgba(234, 179, 8, 0.1); }

.execution-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.execution-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.execution-icon { font-size: 1.25rem; }
.execution-title { font-weight: 600; color: var(--text-color); }
.execution-id {
  font-family: monospace;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}
.execution-error {
  margin-top: 0.5rem;
  padding: 0.75rem;
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 4px;
  color: #ef4444;
  font-size: 0.9rem;
  font-family: monospace;
  white-space: pre-wrap;
  word-break: break-word;
}
.execution-logs {
  margin-top: 0.5rem;
  max-height: 200px;
  overflow: auto;
  background: var(--surface-ground);
  border-radius: 4px;
  padding: 0.5rem;
}
.execution-logs pre {
  margin: 0;
  font-size: 0.8rem;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-color);
}
.execution-actions {
  margin-top: 0.75rem;
  display: flex;
  gap: 0.5rem;
}

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
.summary-card.critical { border-left-color: var(--red-500); }
.summary-card.high { border-left-color: var(--orange-500); }
.summary-card.medium { border-left-color: var(--yellow-500); }
.summary-card.info { border-left-color: var(--blue-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { margin-bottom: 1rem; }
.text-danger { color: var(--red-500); }
.text-success { color: var(--green-500); }
</style>
