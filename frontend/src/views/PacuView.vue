<template>
  <div class="pacu-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Pacu</h1>
        <p class="subtitle">
          AWS exploitation framework results
        </p>
      </div>
      <div class="header-actions">
        <Button
          v-if="!isRunning"
          v-tooltip.left="!hasAwsCredentials ? 'Set up AWS credentials first' : ''"
          label="Run Module"
          icon="pi pi-play"
          :loading="store.loading"
          :disabled="!hasAwsCredentials"
          @click="showModuleDialog = true"
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

    <!-- No Credentials Warning -->
    <div
      v-if="!hasAwsCredentials"
      class="no-credentials-warning"
    >
      <i class="pi pi-info-circle" />
      <span>AWS credentials required. Go to <router-link to="/credentials">Credentials</router-link>, verify your credentials, and click "Use for Scans".</span>
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
          v-if="store.currentExecution.status === 'completed' || store.currentExecution.status === 'failed'"
          label="View Logs"
          size="small"
          @click="fetchExecutionLogs"
        />
      </div>
    </div>

    <!-- Module Selection Dialog -->
    <Dialog
      v-model:visible="showModuleDialog"
      header="Run Pacu Module"
      :style="{ width: '450px' }"
    >
      <div class="module-form">
        <div class="field">
          <label for="module">Module</label>
          <Dropdown
            id="module"
            v-model="selectedModule"
            :options="pacuModules"
            placeholder="Select a module"
            class="w-full"
          />
        </div>
        <div class="field">
          <label for="session">Session Name</label>
          <InputText
            id="session"
            v-model="sessionName"
            placeholder="api-session"
            class="w-full"
          />
        </div>
      </div>
      <template #footer>
        <Button
          label="Cancel"
          text
          @click="showModuleDialog = false"
        />
        <Button
          label="Run"
          icon="pi pi-play"
          :disabled="!selectedModule"
          @click="runModule"
        />
      </template>
    </Dialog>

    <!-- Result Details Dialog -->
    <Dialog
      v-model:visible="showResultDialog"
      header="Execution Details"
      :style="{ width: '700px' }"
    >
      <div
        v-if="selectedResult"
        class="result-details"
      >
        <div class="detail-grid">
          <div class="detail-item">
            <label>Module</label>
            <span class="value">{{ selectedResult.module_name }}</span>
          </div>
          <div class="detail-item">
            <label>Category</label>
            <span class="value">{{ selectedResult.module_category }}</span>
          </div>
          <div class="detail-item">
            <label>Session</label>
            <span class="value">{{ selectedResult.session_name }}</span>
          </div>
          <div class="detail-item">
            <label>Status</label>
            <Tag
              :severity="getStatusSeverity(selectedResult.execution_status)"
              :value="selectedResult.execution_status"
            />
          </div>
          <div class="detail-item">
            <label>Account ID</label>
            <span class="value">{{ selectedResult.target_account_id || 'N/A' }}</span>
          </div>
          <div class="detail-item">
            <label>Resources Affected</label>
            <span class="value">{{ selectedResult.resources_affected }}</span>
          </div>
          <div class="detail-item">
            <label>Duration</label>
            <span class="value">{{ selectedResult.execution_time_ms ? (selectedResult.execution_time_ms / 1000).toFixed(2) + 's' : 'N/A' }}</span>
          </div>
          <div class="detail-item">
            <label>Result ID</label>
            <span class="value mono">{{ selectedResult.result_id }}</span>
          </div>
        </div>
        <div
          v-if="selectedResult.error_message"
          class="error-section"
        >
          <label>Error Details</label>
          <pre class="error-content">{{ selectedResult.error_message }}</pre>
        </div>
        <div
          v-if="resultLogs"
          class="logs-section"
        >
          <label>Execution Logs</label>
          <pre class="logs-content">{{ resultLogs }}</pre>
        </div>
      </div>
      <template #footer>
        <Button
          label="View Logs"
          icon="pi pi-file"
          :loading="logsLoading"
          @click="fetchResultLogs"
        />
        <Button
          label="Close"
          @click="showResultDialog = false"
        />
      </template>
    </Dialog>

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_executions }}
        </div>
        <div class="card-label">
          Total Executions
        </div>
      </div>
      <div class="summary-card success">
        <div class="card-value">
          {{ store.summary.successful }}
        </div>
        <div class="card-label">
          Successful
        </div>
      </div>
      <div class="summary-card danger">
        <div class="card-value">
          {{ store.summary.failed }}
        </div>
        <div class="card-label">
          Failed
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Dropdown
        v-model="filters.moduleCategory"
        :options="categoryOptions"
        placeholder="Category"
        class="filter-dropdown"
        @change="applyFilters"
      />
      <Dropdown
        v-model="filters.executionStatus"
        :options="statusOptions"
        placeholder="Status"
        class="filter-dropdown"
        @change="applyFilters"
      />
    </div>

    <DataTable
      :value="store.results"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="module_name"
        header="Module"
      />
      <Column
        field="module_category"
        header="Category"
      />
      <Column
        field="session_name"
        header="Session"
      />
      <Column
        field="execution_status"
        header="Status"
      >
        <template #body="{ data }">
          <Tag
            :severity="getStatusSeverity(data.execution_status)"
            :value="data.execution_status"
          />
        </template>
      </Column>
      <Column
        field="resources_affected"
        header="Resources"
      />
      <Column
        field="execution_time_ms"
        header="Duration (ms)"
      />
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            icon="pi pi-eye"
            text
            @click="viewResult(data)"
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
import { usePacuStore } from '../stores/pacu'
import { useExecutionsStore } from '../stores/executions'
import { useCredentialsStore } from '../stores/credentials'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import Paginator from 'primevue/paginator'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'

const store = usePacuStore()
const executionsStore = useExecutionsStore()
const credentialsStore = useCredentialsStore()

// Check if AWS credentials are available in session
// Access the reactive sessionCredentials directly for proper reactivity
const hasAwsCredentials = computed(() => {
  const creds = credentialsStore.sessionCredentials.aws
  return creds && creds.access_key_id && creds.secret_access_key
})

const filters = ref({
  moduleCategory: null,
  executionStatus: null,
})

const showModuleDialog = ref(false)
const selectedModule = ref(null)
const sessionName = ref('')
const executionLogs = ref(null)

// Result details dialog
const showResultDialog = ref(false)
const selectedResult = ref(null)
const resultLogs = ref(null)
const logsLoading = ref(false)

const categoryOptions = ['ENUM', 'PRIVESC', 'PERSIST', 'EXFIL', 'EXPLOIT', 'DETECTION']
const statusOptions = ['success', 'failed', 'running']

// Actual Pacu module names from the tool
const pacuModules = [
  // ENUM
  'iam__enum_permissions',
  'iam__enum_users_roles_policies_groups',
  'iam__bruteforce_permissions',
  'ec2__enum',
  'lambda__enum',
  'rds__enum',
  'ecs__enum',
  'eks__enum',
  'sns__enum',
  'secrets__enum',
  'dynamodb__enum',
  'ebs__enum_volumes_snapshots',
  'aws__enum_account',
  // ESCALATE
  'iam__privesc_scan',
  // PERSIST
  'iam__backdoor_users_keys',
  'iam__backdoor_users_password',
  'iam__backdoor_assume_role',
  // EXFIL
  's3__download_bucket',
  'ebs__download_snapshots',
  'rds__explore_snapshots',
  // EVADE
  'detection__enum_services',
  'cloudtrail__download_event_history',
  'guardduty__list_findings',
]

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
    running: 'Pacu module running...',
    completed: 'Pacu module completed',
    failed: 'Pacu module failed',
    pending: 'Pacu module pending',
  }
  return titles[status] || 'Pacu module'
})

function getStatusSeverity(status) {
  const map = { success: 'success', failed: 'danger', running: 'info' }
  return map[status] || 'secondary'
}

function applyFilters() {
  store.setFilters(filters.value)
}

function viewResult(result) {
  selectedResult.value = result
  resultLogs.value = null
  showResultDialog.value = true
}

async function fetchResultLogs() {
  if (!selectedResult.value?.result_id) return
  logsLoading.value = true
  try {
    const response = await fetch(`/api/executions/${selectedResult.value.result_id}/logs?tail=500`)
    const data = await response.json()
    resultLogs.value = data.logs || 'No logs available'
  } catch (error) {
    resultLogs.value = `Error fetching logs: ${error.message}`
  } finally {
    logsLoading.value = false
  }
}

async function fetchExecutionLogs() {
  if (!store.currentExecution?.execution_id) return
  try {
    const response = await fetch(`/api/executions/${store.currentExecution.execution_id}/logs?tail=500`)
    const data = await response.json()
    executionLogs.value = data.logs || 'No logs available'
  } catch (error) {
    executionLogs.value = `Error fetching logs: ${error.message}`
  }
}

async function runModule() {
  showModuleDialog.value = false
  executionLogs.value = null
  await store.runModule({
    module: selectedModule.value,
    session_name: sessionName.value || 'api-session',
  })
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
  store.fetchResults()
}

onMounted(() => {
  store.fetchResults()
  store.fetchSummary()
  store.fetchModules()
})

onUnmounted(() => {
  // Stop any polling when leaving the view
  if (store.currentExecution?.execution_id) {
    executionsStore.stopPolling(store.currentExecution.execution_id)
  }
})
</script>

<style scoped>
.pacu-view { padding: 1.5rem; }
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
.execution-panel.status-running {
  border-left-color: var(--blue-500);
  background: rgba(59, 130, 246, 0.1);
}
.execution-panel.status-completed {
  border-left-color: var(--green-500);
  background: rgba(34, 197, 94, 0.1);
}
.execution-panel.status-failed {
  border-left-color: var(--red-500);
  background: rgba(239, 68, 68, 0.1);
}
.execution-panel.status-pending {
  border-left-color: var(--yellow-500);
  background: rgba(234, 179, 8, 0.1);
}

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

.module-form .field {
  margin-bottom: 1rem;
}
.module-form label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}
.w-full { width: 100%; }

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
.summary-card.success { border-left-color: var(--green-500); }
.summary-card.danger { border-left-color: var(--red-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
.filter-dropdown { min-width: 150px; }

.no-credentials-warning {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  margin-bottom: 1.5rem;
  background: rgba(234, 179, 8, 0.1);
  border: 1px solid rgba(234, 179, 8, 0.3);
  border-left: 4px solid var(--yellow-500);
  border-radius: 8px;
  color: var(--text-color);
}
.no-credentials-warning i {
  font-size: 1.25rem;
  color: var(--yellow-500);
}
.no-credentials-warning a {
  color: var(--primary-color);
  font-weight: 500;
}

/* Result Details Dialog */
.result-details { padding: 0.5rem 0; }
.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1rem;
  margin-bottom: 1rem;
}
.detail-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.detail-item label {
  font-size: 0.85rem;
  color: var(--text-color-secondary);
  font-weight: 500;
}
.detail-item .value {
  font-size: 1rem;
  color: var(--text-color);
}
.detail-item .value.mono {
  font-family: monospace;
  font-size: 0.9rem;
}
.error-section, .logs-section {
  margin-top: 1rem;
}
.error-section label, .logs-section label {
  display: block;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
  font-weight: 500;
  margin-bottom: 0.5rem;
}
.error-content {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 4px;
  padding: 0.75rem;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 200px;
  overflow: auto;
  color: #ef4444;
}
.logs-content {
  background: var(--surface-ground);
  border: 1px solid var(--surface-border);
  border-radius: 4px;
  padding: 0.75rem;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 300px;
  overflow: auto;
  color: var(--text-color);
}
</style>
