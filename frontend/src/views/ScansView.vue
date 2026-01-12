<template>
  <div class="scans-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Scans</h1>
        <p class="subtitle">
          Launch security scans and monitor execution status
        </p>
      </div>
      <div class="header-actions">
        <Button
          label="New Scan"
          icon="pi pi-plus"
          :disabled="store.hasRunningScans"
          @click="showNewScanDialog = true"
        />
      </div>
    </div>

    <!-- Credential Status Section -->
    <section class="section">
      <h2 class="section-title">
        Credential Status
      </h2>
      <div class="credential-cards">
        <div
          class="credential-card"
          :class="getStatusClass(store.awsStatus)"
          @click="$router.push('/credentials')"
        >
          <div class="provider-icon">
            <i class="pi pi-cloud" />
          </div>
          <div class="provider-info">
            <span class="provider-name">AWS</span>
            <span class="provider-status">{{ formatStatus(store.awsStatus) }}</span>
          </div>
          <div
            class="status-indicator"
            :class="store.awsStatus"
          />
        </div>

        <div
          class="credential-card"
          :class="getStatusClass(store.azureStatus)"
          @click="$router.push('/credentials')"
        >
          <div class="provider-icon">
            <i class="pi pi-microsoft" />
          </div>
          <div class="provider-info">
            <span class="provider-name">Azure</span>
            <span class="provider-status">{{ formatStatus(store.azureStatus) }}</span>
          </div>
          <div
            class="status-indicator"
            :class="store.azureStatus"
          />
        </div>

        <div
          class="credential-card"
          :class="getStatusClass(store.gcpStatus)"
          @click="$router.push('/credentials')"
        >
          <div class="provider-icon">
            <i class="pi pi-google" />
          </div>
          <div class="provider-info">
            <span class="provider-name">GCP</span>
            <span class="provider-status">{{ formatStatus(store.gcpStatus) }}</span>
          </div>
          <div
            class="status-indicator"
            :class="store.gcpStatus"
          />
        </div>

        <div
          class="credential-card"
          :class="getStatusClass(store.kubernetesStatus)"
          @click="$router.push('/credentials')"
        >
          <div class="provider-icon">
            <i class="pi pi-server" />
          </div>
          <div class="provider-info">
            <span class="provider-name">Kubernetes</span>
            <span class="provider-status">{{ formatStatus(store.kubernetesStatus) }}</span>
          </div>
          <div
            class="status-indicator"
            :class="store.kubernetesStatus"
          />
        </div>
      </div>
      <div class="credential-actions">
        <Button
          label="Configure Credentials"
          icon="pi pi-cog"
          severity="secondary"
          size="small"
          @click="$router.push('/credentials')"
        />
      </div>
    </section>

    <!-- Quick Actions Section -->
    <section class="section">
      <h2 class="section-title">
        Quick Actions
      </h2>
      <div class="profile-cards">
        <div
          v-for="profile in store.profiles"
          :key="profile.id"
          class="profile-card"
          @click="startQuickScan(profile.id)"
        >
          <div class="profile-header">
            <h3>{{ profile.name }}</h3>
            <span class="profile-time">{{ profile.estimatedTime }}</span>
          </div>
          <p class="profile-description">
            {{ profile.description }}
          </p>
          <Button
            label="Start"
            icon="pi pi-play"
            size="small"
            class="profile-start-btn"
            :loading="store.loading && selectedProfile === profile.id"
            :disabled="store.hasRunningScans"
          />
        </div>
      </div>
    </section>

    <!-- Recent Scans Section -->
    <section class="section">
      <div class="section-header">
        <h2 class="section-title">
          Recent Scans
        </h2>
        <Button
          label="View All"
          icon="pi pi-list"
          text
          size="small"
          @click="viewAllScans"
        />
      </div>

      <div
        v-if="store.loading && store.scans.length === 0"
        class="loading-container"
      >
        <ProgressSpinner />
        <span>Loading scans...</span>
      </div>

      <div
        v-else-if="store.scans.length === 0"
        class="empty-state"
      >
        <i class="pi pi-search" />
        <p>No scans yet. Start a scan to begin security assessment.</p>
      </div>

      <DataTable
        v-else
        :value="store.scans"
        responsive-layout="scroll"
        class="p-datatable-sm"
        @row-click="viewScan"
      >
        <Column
          field="scan_id"
          header="ID"
        >
          <template #body="{ data }">
            <span class="scan-id">{{ data.scan_id?.slice(0, 8) || '-' }}</span>
          </template>
        </Column>
        <Column
          field="scan_type"
          header="Profile"
        >
          <template #body="{ data }">
            {{ data.scan_type || data.tool || 'N/A' }}
          </template>
        </Column>
        <Column
          field="status"
          header="Status"
        >
          <template #body="{ data }">
            <Tag
              :severity="getStatusSeverity(data.status)"
              :value="data.status"
            />
          </template>
        </Column>
        <Column
          field="total_findings"
          header="Findings"
        >
          <template #body="{ data }">
            <span v-if="data.status === 'completed'">{{ data.total_findings || 0 }}</span>
            <span v-else>-</span>
          </template>
        </Column>
        <Column
          field="started_at"
          header="Started"
        >
          <template #body="{ data }">
            {{ formatDate(data.started_at) }}
          </template>
        </Column>
        <Column header="Actions">
          <template #body="{ data }">
            <Button
              v-if="data.status === 'running'"
              icon="pi pi-stop"
              severity="danger"
              text
              size="small"
              @click.stop="cancelScan(data.scan_id)"
            />
            <Button
              icon="pi pi-eye"
              text
              size="small"
              @click.stop="viewScan({ data })"
            />
          </template>
        </Column>
      </DataTable>
    </section>

    <!-- New Scan Dialog -->
    <Dialog
      v-model:visible="showNewScanDialog"
      modal
      header="Start New Scan"
      :style="{ width: '500px' }"
    >
      <div class="new-scan-form">
        <div class="form-field">
          <label>Scan Profile</label>
          <Dropdown
            v-model="newScanConfig.profile"
            :options="store.profiles"
            option-label="name"
            option-value="id"
            placeholder="Select a profile"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Cloud Provider</label>
          <Dropdown
            v-model="newScanConfig.provider"
            :options="providerOptions"
            option-label="label"
            option-value="value"
            placeholder="Select a provider"
            class="w-full"
            show-clear
            @change="onProviderChange"
          />
        </div>

        <div
          v-if="newScanConfig.provider"
          class="form-field"
        >
          <label>Tools (optional - leave empty for profile defaults)</label>
          <MultiSelect
            v-model="newScanConfig.tools"
            :options="toolOptions"
            option-label="label"
            option-value="value"
            placeholder="Select specific tools or use profile defaults"
            class="w-full"
            display="chip"
          />
        </div>

        <div class="form-field">
          <label>Target (optional)</label>
          <InputText
            v-model="newScanConfig.target"
            placeholder="e.g., specific account or resource"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Severity Filter</label>
          <MultiSelect
            v-model="newScanConfig.severities"
            :options="severityOptions"
            option-label="label"
            option-value="value"
            placeholder="All severities"
            class="w-full"
          />
        </div>

        <div class="form-field checkbox-field">
          <Checkbox
            v-model="newScanConfig.dryRun"
            binary
            input-id="dryRun"
          />
          <label for="dryRun">Dry Run (preview commands without execution)</label>
        </div>
      </div>

      <template #footer>
        <Button
          label="Cancel"
          text
          @click="showNewScanDialog = false"
        />
        <Button
          label="Start Scan"
          icon="pi pi-play"
          :loading="store.loading"
          @click="startScan"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useScansStore } from '../stores/scans'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Dropdown from 'primevue/dropdown'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Checkbox from 'primevue/checkbox'
import ProgressSpinner from 'primevue/progressspinner'

const router = useRouter()
const store = useScansStore()
const toast = useToast()

// Initialize toast in store for notifications
store.setToast(toast)

const showNewScanDialog = ref(false)
const selectedProfile = ref(null)
const newScanConfig = ref({
  profile: 'comprehensive',
  target: '',
  severities: [],
  provider: null,
  tools: [],
  dryRun: false,
})

const toolOptions = ref([])

const providerOptions = [
  { label: 'AWS', value: 'aws' },
  { label: 'Azure', value: 'azure' },
  { label: 'GCP', value: 'gcp' },
  { label: 'Kubernetes', value: 'kubernetes' },
  { label: 'IaC', value: 'iac' },
]

const severityOptions = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
]

function formatToolName(tool) {
  // Convert tool name to display format (e.g., "kube-bench" -> "Kube Bench")
  return tool
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

async function onProviderChange() {
  // Clear previously selected tools when provider changes
  newScanConfig.value.tools = []

  if (newScanConfig.value.provider) {
    const tools = await store.fetchToolsForProvider(newScanConfig.value.provider)
    toolOptions.value = tools.map(tool => ({
      label: formatToolName(tool),
      value: tool,
    }))
  } else {
    toolOptions.value = []
  }
}

function getStatusClass(status) {
  return {
    'status-ready': status === 'ready',
    'status-partial': status === 'partial',
    'status-failed': status === 'failed',
    'status-unknown': status === 'unknown',
  }
}

function formatStatus(status) {
  const labels = {
    ready: 'Ready',
    partial: 'Partial',
    failed: 'Not Configured',
    unknown: 'Unknown',
  }
  return labels[status] || status
}

function getStatusSeverity(status) {
  const map = {
    running: 'info',
    completed: 'success',
    failed: 'danger',
    cancelled: 'warning',
    pending: 'secondary',
  }
  return map[status] || 'secondary'
}

function formatDate(dateStr) {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  const now = new Date()
  const diff = now - date

  if (diff < 60000) return 'Just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return date.toLocaleDateString()
}

async function startQuickScan(profileId) {
  selectedProfile.value = profileId
  try {
    await store.createScan({ profile: profileId })
  } catch (e) {
    console.error('Failed to start scan:', e)
  } finally {
    selectedProfile.value = null
  }
}

async function startScan() {
  try {
    await store.createScan({
      profile: newScanConfig.value.profile,
      provider: newScanConfig.value.provider || null,
      tools: newScanConfig.value.tools.length > 0 ? newScanConfig.value.tools : null,
      target: newScanConfig.value.target || null,
      severityFilter: newScanConfig.value.severities.length > 0
        ? newScanConfig.value.severities.join(',')
        : null,
      dryRun: newScanConfig.value.dryRun,
    })
    showNewScanDialog.value = false
    // Reset form
    newScanConfig.value = {
      profile: 'comprehensive',
      target: '',
      severities: [],
      provider: null,
      tools: [],
      dryRun: false,
    }
    toolOptions.value = []
  } catch (e) {
    console.error('Failed to start scan:', e)
  }
}

async function cancelScan(scanId) {
  try {
    await store.cancelScan(scanId)
  } catch (e) {
    console.error('Failed to cancel scan:', e)
  }
}

function viewScan({ data }) {
  if (data?.scan_id) {
    router.push(`/scans/${data.scan_id}`)
  }
}

function viewAllScans() {
  store.pagination.page = 1
  store.fetchScans()
}

onMounted(async () => {
  await Promise.all([
    store.fetchScans(),
    store.fetchProfiles(),
    store.fetchCredentialStatus(),
  ])

  // Start polling for running scans
  for (const scan of store.runningScans) {
    store.startPolling(scan.scan_id)
  }
})

onUnmounted(() => {
  store.stopAllPolling()
})
</script>

<style scoped>
.scans-view {
  max-width: 1400px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-xl);
}

.page-header h1 {
  font-size: 1.75rem;
  font-weight: 700;
  margin: 0;
}

.subtitle {
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

.section {
  margin-bottom: var(--spacing-xl);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0 0 var(--spacing-md) 0;
}

/* Credential Cards */
.credential-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
}

@media (max-width: 1024px) {
  .credential-cards {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 640px) {
  .credential-cards {
    grid-template-columns: 1fr;
  }
}

.credential-card {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: all var(--transition-normal);
  position: relative;
}

.credential-card:hover {
  border-color: var(--border-color-light);
  box-shadow: var(--shadow-md);
}

.credential-card.status-ready {
  border-left: 4px solid var(--green-500);
}

.credential-card.status-partial {
  border-left: 4px solid var(--yellow-500);
}

.credential-card.status-failed,
.credential-card.status-unknown {
  border-left: 4px solid var(--surface-400);
}

.provider-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-md);
  background: var(--accent-primary-bg);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--accent-primary);
  font-size: 1.25rem;
}

.provider-info {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.provider-name {
  font-weight: 600;
  color: var(--text-primary);
}

.provider-status {
  font-size: 0.8125rem;
  color: var(--text-secondary);
}

.status-indicator {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--surface-400);
}

.status-indicator.ready {
  background: var(--green-500);
}

.status-indicator.partial {
  background: var(--yellow-500);
}

.credential-actions {
  margin-top: var(--spacing-md);
}

/* Profile Cards */
.profile-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--spacing-md);
}

@media (max-width: 1024px) {
  .profile-cards {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 640px) {
  .profile-cards {
    grid-template-columns: 1fr;
  }
}

.profile-card {
  padding: var(--spacing-lg);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: all var(--transition-normal);
}

.profile-card:hover {
  border-color: var(--accent-primary);
  box-shadow: var(--shadow-md);
}

.profile-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.profile-header h3 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
}

.profile-time {
  font-size: 0.75rem;
  color: var(--text-secondary);
  background: var(--bg-tertiary);
  padding: 2px 8px;
  border-radius: var(--radius-sm);
}

.profile-description {
  color: var(--text-secondary);
  font-size: 0.875rem;
  margin-bottom: var(--spacing-md);
}

.profile-start-btn {
  width: 100%;
}

/* Scan Table */
.scan-id {
  font-family: monospace;
  font-size: 0.8125rem;
  color: var(--text-secondary);
}

/* Empty State */
.empty-state {
  text-align: center;
  padding: var(--spacing-xl) * 2;
  color: var(--text-secondary);
}

.empty-state i {
  font-size: 3rem;
  margin-bottom: var(--spacing-md);
  opacity: 0.5;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: var(--spacing-xl);
  color: var(--text-secondary);
  gap: var(--spacing-md);
}

/* New Scan Form */
.new-scan-form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.form-field {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.form-field label {
  font-weight: 500;
  font-size: 0.875rem;
}

.checkbox-field {
  flex-direction: row;
  align-items: center;
  gap: var(--spacing-sm);
}

.w-full {
  width: 100%;
}
</style>
