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

    <!-- IaC Security Scanning Section -->
    <section class="section">
      <h2 class="section-title">
        IaC Security Scanning
      </h2>
      <div class="iac-scanning-card">
        <div class="iac-info">
          <i class="pi pi-file-edit iac-icon" />
          <div class="iac-content">
            <h3>Infrastructure-as-Code Security</h3>
            <p>Upload Terraform, CloudFormation, Kubernetes manifests, or Helm charts for security analysis. No cloud credentials required.</p>
          </div>
        </div>
        <Button
          label="Upload Files"
          icon="pi pi-upload"
          @click="showIaCUploadDialog = true"
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
        >
          <div class="profile-header">
            <h3>{{ profile.name }}</h3>
            <span class="profile-time">{{ profile.estimatedTime }}</span>
          </div>
          <p class="profile-description">
            {{ profile.description }}
          </p>
          <div class="profile-provider-toggles">
            <button
              v-for="cp in cloudProviders"
              :key="cp.value"
              type="button"
              class="profile-provider-btn"
              :class="{
                'active': getQuickScanProviders(profile.id)[cp.value],
                'disabled': !isProviderReady(cp.value)
              }"
              :disabled="!isProviderReady(cp.value)"
              @click.stop="toggleQuickProvider(profile.id, cp.value)"
            >
              <i :class="cp.icon" />
              <span>{{ cp.label }}</span>
              <i
                v-if="getQuickScanProviders(profile.id)[cp.value]"
                class="pi pi-check check-mark"
              />
            </button>
          </div>
          <Button
            label="Start"
            icon="pi pi-play"
            size="small"
            class="profile-start-btn"
            :loading="store.loading && selectedProfile === profile.id"
            :disabled="store.hasRunningScans || !hasQuickProviderSelected(profile.id)"
            @click.stop="startQuickScan(profile.id)"
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

      <!-- Bulk Actions Toolbar -->
      <div
        v-if="store.selectedScans.length > 0"
        class="bulk-actions-bar"
      >
        <span class="selection-count">{{ store.selectedScans.length }} scan(s) selected</span>
        <div class="bulk-buttons">
          <Button
            label="Delete Selected"
            icon="pi pi-trash"
            severity="danger"
            size="small"
            :loading="store.bulkOperationLoading"
            @click="confirmBulkDelete"
          />
          <Button
            label="Archive Selected"
            icon="pi pi-file-export"
            size="small"
            :loading="store.bulkOperationLoading"
            @click="confirmBulkArchive"
          />
          <Button
            label="Clear Selection"
            icon="pi pi-times"
            text
            size="small"
            @click="store.clearSelection"
          />
        </div>
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
        v-model:selection="store.selectedScans"
        :value="store.scans"
        data-key="scan_id"
        responsive-layout="scroll"
        class="p-datatable-sm"
        @row-click="viewScan"
      >
        <Column
          selection-mode="multiple"
          header-style="width: 3rem"
        >
          <template #body="{ data }">
            <Checkbox
              v-model="store.selectedScans"
              :value="data"
              :disabled="data.status === 'running' || data.status === 'pending'"
              @click.stop
            />
          </template>
        </Column>
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
            <div class="status-cell">
              <Tag
                v-tooltip.top="getStatusTooltip(data)"
                :severity="getStatusSeverity(data.status)"
                :value="data.status"
                :class="{ 'cursor-pointer': data.status === 'failed' }"
                @click="data.status === 'failed' && showScanErrors(data.scan_id)"
              />
              <span
                v-if="data.status === 'running' && getToolProgressCount(data)"
                class="mini-progress"
              >
                {{ getToolProgressCount(data) }}
              </span>
            </div>
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

    <!-- Delete Confirmation Dialog -->
    <Dialog
      v-model:visible="showDeleteConfirm"
      modal
      header="Confirm Delete"
      :style="{ width: '400px' }"
    >
      <p>Are you sure you want to delete {{ store.selectedScans.length }} scan(s)?</p>
      <p class="confirm-warning">
        This will also delete all associated report files.
      </p>
      <template #footer>
        <Button
          label="Cancel"
          text
          @click="showDeleteConfirm = false"
        />
        <Button
          label="Delete"
          icon="pi pi-trash"
          severity="danger"
          :loading="store.bulkOperationLoading"
          @click="handleBulkDelete"
        />
      </template>
    </Dialog>

    <!-- Archive Confirmation Dialog -->
    <Dialog
      v-model:visible="showArchiveConfirm"
      modal
      header="Confirm Archive"
      :style="{ width: '400px' }"
    >
      <p>Are you sure you want to archive {{ store.selectedScans.length }} scan(s)?</p>
      <p class="confirm-info">
        A zip archive will be created and original files will be deleted.
      </p>
      <template #footer>
        <Button
          label="Cancel"
          text
          @click="showArchiveConfirm = false"
        />
        <Button
          label="Archive"
          icon="pi pi-file-export"
          :loading="store.bulkOperationLoading"
          @click="handleBulkArchive"
        />
      </template>
    </Dialog>

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
          <label>Cloud Providers</label>
          <div class="provider-toggles">
            <div
              v-for="provider in cloudProviders"
              :key="provider.value"
              class="provider-toggle-wrapper"
            >
              <button
                type="button"
                class="provider-toggle"
                :class="{
                  'active': selectedProviders[provider.value],
                  'disabled': !isProviderReady(provider.value)
                }"
                :disabled="!isProviderReady(provider.value)"
                @click="toggleProvider(provider.value)"
              >
                <i :class="provider.icon" />
                <span>{{ provider.label }}</span>
                <i
                  v-if="selectedProviders[provider.value]"
                  class="pi pi-check check-icon"
                />
              </button>
              <span
                v-if="!isProviderReady(provider.value)"
                class="provider-status-hint"
              >Not configured</span>
            </div>
          </div>
          <small class="helper-text">Select one or more cloud providers to scan</small>
        </div>

        <div
          v-if="hasSelectedProviders"
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

    <!-- Scan Error Details Dialog -->
    <Dialog
      v-model:visible="showErrorDialog"
      modal
      header="Scan Error Details"
      :style="{ width: '600px' }"
    >
      <div
        v-if="scanErrorDetails"
        class="error-details"
      >
        <div
          v-if="scanErrorDetails.error"
          class="error-summary"
        >
          <i class="pi pi-exclamation-triangle error-icon" />
          <span>{{ scanErrorDetails.error }}</span>
        </div>

        <div
          v-if="Object.keys(scanErrorDetails.tool_errors || {}).length > 0 || (scanErrorDetails.completed_tools || []).length > 0"
          class="tool-status-list"
        >
          <h4>Tool Status</h4>
          <div
            v-for="tool in scanErrorDetails.tools_planned"
            :key="tool"
            class="tool-status-item"
          >
            <Tag
              :severity="getToolStatusSeverity(tool, scanErrorDetails)"
              :value="getToolStatusLabel(tool, scanErrorDetails)"
              class="tool-status-tag"
            />
            <span class="tool-name">{{ formatToolName(tool) }}</span>
            <span
              v-if="scanErrorDetails.tool_errors && scanErrorDetails.tool_errors[tool]"
              class="tool-error-msg"
            >
              {{ scanErrorDetails.tool_errors[tool] }}
            </span>
          </div>
        </div>

        <div
          v-if="!scanErrorDetails.error && Object.keys(scanErrorDetails.tool_errors || {}).length === 0"
          class="no-error-info"
        >
          <i class="pi pi-info-circle" />
          <span>No detailed error information available</span>
        </div>
      </div>
      <div
        v-else
        class="loading-errors"
      >
        <ProgressSpinner
          style="width: 40px; height: 40px"
          stroke-width="4"
        />
        <span>Loading error details...</span>
      </div>
      <template #footer>
        <Button
          label="Close"
          icon="pi pi-times"
          text
          @click="showErrorDialog = false"
        />
      </template>
    </Dialog>

    <!-- IaC Upload Dialog -->
    <Dialog
      v-model:visible="showIaCUploadDialog"
      modal
      header="IaC Security Scanning"
      :style="{ width: '600px' }"
    >
      <IaCUpload
        @cancel="showIaCUploadDialog = false"
        @scan-started="onIaCScanStarted"
      />
    </Dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useScansStore } from '../stores/scans'
import { useCredentialsStore, onCredentialStatusChange } from '../stores/credentials'
import { api } from '../services/api'
import { toast } from '../services/toast'
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
import IaCUpload from '../components/scans/IaCUpload.vue'

const router = useRouter()
const store = useScansStore()
const credentialsStore = useCredentialsStore()

const showNewScanDialog = ref(false)
const showErrorDialog = ref(false)
const showIaCUploadDialog = ref(false)
const scanErrorDetails = ref(null)
const showDeleteConfirm = ref(false)
const showArchiveConfirm = ref(false)
const selectedProfile = ref(null)

// Track selected providers for each Quick Action profile card
const quickScanProviders = ref({})

// Initialize provider selection for a profile (lazy init)
function getQuickScanProviders(profileId) {
  if (!quickScanProviders.value[profileId]) {
    quickScanProviders.value[profileId] = {
      aws: false,
      azure: false,
      gcp: false,
      kubernetes: false,
      iac: false,
    }
  }
  return quickScanProviders.value[profileId]
}

// Toggle provider for a Quick Action card
function toggleQuickProvider(profileId, provider) {
  const providers = getQuickScanProviders(profileId)
  if (isProviderReady(provider)) {
    providers[provider] = !providers[provider]
  }
}

// Check if a Quick Action card has at least one provider selected
function hasQuickProviderSelected(profileId) {
  const providers = quickScanProviders.value[profileId]
  if (!providers) return false
  return Object.values(providers).some(v => v)
}

// Get list of selected providers for a Quick Action card
function getQuickSelectedProviders(profileId) {
  const providers = quickScanProviders.value[profileId]
  if (!providers) return []
  return Object.entries(providers)
    .filter(([, selected]) => selected)
    .map(([provider]) => provider)
}

const newScanConfig = ref({
  profile: 'comprehensive',
  target: '',
  severities: [],
  tools: [],
  dryRun: false,
})

// Provider selection state
const selectedProviders = ref({
  aws: false,
  azure: false,
  gcp: false,
  kubernetes: false,
  iac: false,
})

const toolOptions = ref([])

const cloudProviders = [
  { label: 'AWS', value: 'aws', icon: 'pi pi-cloud' },
  { label: 'Azure', value: 'azure', icon: 'pi pi-microsoft' },
  { label: 'GCP', value: 'gcp', icon: 'pi pi-google' },
  { label: 'Kubernetes', value: 'kubernetes', icon: 'pi pi-box' },
  { label: 'IaC', value: 'iac', icon: 'pi pi-file-edit' },
]

// Check if a provider has valid credentials
function isProviderReady(provider) {
  if (provider === 'aws') {
    return store.awsStatus === 'ready'
  }
  if (provider === 'azure') {
    return store.azureStatus === 'ready'
  }
  if (provider === 'gcp') {
    return store.gcpStatus === 'ready'
  }
  if (provider === 'kubernetes') {
    return store.kubernetesStatus === 'ready'
  }
  if (provider === 'iac') {
    // IaC scanning doesn't require credentials
    return true
  }
  return false
}

// Toggle provider selection
function toggleProvider(provider) {
  selectedProviders.value[provider] = !selectedProviders.value[provider]
  // When toggling, update tool options for selected providers
  updateToolOptions()
}

// Check if any provider is selected
const hasSelectedProviders = computed(() => {
  return Object.values(selectedProviders.value).some(v => v)
})

// Get list of selected provider values
function getSelectedProviderList() {
  return Object.entries(selectedProviders.value)
    .filter(([, selected]) => selected)
    .map(([provider]) => provider)
}

// Update tool options based on selected providers
async function updateToolOptions() {
  const selected = getSelectedProviderList()
  if (selected.length === 0) {
    toolOptions.value = []
    return
  }

  // Get tools for each selected provider
  const allTools = []
  for (const provider of selected) {
    const tools = await store.fetchToolsForProvider(provider)
    allTools.push(...tools.map(tool => ({
      label: formatToolName(tool),
      value: tool,
      provider,
    })))
  }
  toolOptions.value = allTools
}

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

function getStatusTooltip(scan) {
  if (scan.status === 'failed' && scan.scan_metadata?.error) {
    return `Error: ${scan.scan_metadata.error} (click for details)`
  }
  return null
}

function getToolProgressCount(scan) {
  if (!scan?.scan_metadata?.tools?.length) return null
  const tools = scan.scan_metadata.tools
  const completedTools = scan.scan_metadata.completed_tools || []
  return `${completedTools.length}/${tools.length}`
}

async function showScanErrors(scanId) {
  showErrorDialog.value = true
  scanErrorDetails.value = null
  try {
    scanErrorDetails.value = await api.getScanErrors(scanId)
  } catch (e) {
    console.error('Failed to fetch scan errors:', e)
    toast.apiError(e, 'Failed to load error details')
    scanErrorDetails.value = { error: 'Failed to load error details' }
  }
}

function getToolStatusSeverity(tool, details) {
  if (details.tool_errors && details.tool_errors[tool]) return 'danger'
  if (details.completed_tools && details.completed_tools.includes(tool)) return 'success'
  return 'secondary'
}

function getToolStatusLabel(tool, details) {
  if (details.tool_errors && details.tool_errors[tool]) return 'Failed'
  if (details.completed_tools && details.completed_tools.includes(tool)) return 'OK'
  return 'Not Run'
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
  const providers = getQuickSelectedProviders(profileId)

  if (providers.length === 0) {
    toast.add({
      severity: 'warn',
      summary: 'Select Provider',
      detail: 'Please select at least one cloud provider to scan',
      life: 4000,
    })
    return
  }

  selectedProfile.value = profileId
  try {
    // Create a scan for each selected provider
    for (const provider of providers) {
      const scanPayload = {
        profile: profileId,
        provider: provider,
      }

      // Inject Azure credentials if Azure provider selected
      if (provider === 'azure') {
        const azureCreds = credentialsStore.getSessionCredentials('azure')
        if (azureCreds) {
          scanPayload.azure_tenant_id = azureCreds.tenant_id
          scanPayload.azure_client_id = azureCreds.client_id
          scanPayload.azure_client_secret = azureCreds.client_secret
          if (azureCreds.subscription_id) {
            scanPayload.azure_subscription_id = azureCreds.subscription_id
          }
        } else {
          toast.add({
            severity: 'error',
            summary: 'Azure Credentials Missing',
            detail: 'Please configure Azure credentials in the Credentials page',
            life: 5000,
          })
          return
        }
      }

      // For AWS, use selected profile
      if (provider === 'aws') {
        if (credentialsStore.selectedAwsProfile) {
          scanPayload.aws_profile = credentialsStore.selectedAwsProfile
        }
      }

      await store.createScan(scanPayload)
    }
  } catch (e) {
    console.error('Failed to start scan:', e)
    toast.apiError(e, 'Failed to start scan')
  } finally {
    selectedProfile.value = null
  }
}

async function startScan() {
  const providers = getSelectedProviderList()

  if (providers.length === 0) {
    toast.add({
      severity: 'warn',
      summary: 'Select Provider',
      detail: 'Please select at least one cloud provider to scan',
      life: 4000,
    })
    return
  }

  try {
    // Create a scan for each selected provider
    for (const provider of providers) {
      const scanPayload = {
        profile: newScanConfig.value.profile,
        provider: provider,
        tools: newScanConfig.value.tools.length > 0 ? newScanConfig.value.tools : null,
        target: newScanConfig.value.target || null,
        severityFilter: newScanConfig.value.severities.length > 0
          ? newScanConfig.value.severities.join(',')
          : null,
        dryRun: newScanConfig.value.dryRun,
      }

      // Inject Azure credentials if Azure provider selected
      if (provider === 'azure') {
        const azureCreds = credentialsStore.getSessionCredentials('azure')
        if (azureCreds) {
          scanPayload.azure_tenant_id = azureCreds.tenant_id
          scanPayload.azure_client_id = azureCreds.client_id
          scanPayload.azure_client_secret = azureCreds.client_secret
          if (azureCreds.subscription_id) {
            scanPayload.azure_subscription_id = azureCreds.subscription_id
          }
        } else {
          toast.add({
            severity: 'error',
            summary: 'Azure Credentials Missing',
            detail: 'Please configure Azure credentials in the Credentials page',
            life: 5000,
          })
          return
        }
      }

      // For AWS, use selected profile
      if (provider === 'aws') {
        if (credentialsStore.selectedAwsProfile) {
          scanPayload.aws_profile = credentialsStore.selectedAwsProfile
        }
      }

      await store.createScan(scanPayload)
    }

    showNewScanDialog.value = false
    // Reset form
    newScanConfig.value = {
      profile: 'comprehensive',
      target: '',
      severities: [],
      tools: [],
      dryRun: false,
    }
    selectedProviders.value = {
      aws: false,
      azure: false,
    }
    toolOptions.value = []
  } catch (e) {
    console.error('Failed to start scan:', e)
    toast.apiError(e, 'Failed to start scan')
  }
}

async function cancelScan(scanId) {
  try {
    await store.cancelScan(scanId)
  } catch (e) {
    console.error('Failed to cancel scan:', e)
    toast.apiError(e, 'Failed to cancel scan')
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

function onIaCScanStarted(scanId) {
  showIaCUploadDialog.value = false
  // Refresh scans list
  store.fetchScans()
  // Start polling for the new scan
  store.startPolling(scanId)
}

// Bulk Operations
function confirmBulkDelete() {
  showDeleteConfirm.value = true
}

function confirmBulkArchive() {
  showArchiveConfirm.value = true
}

async function handleBulkDelete() {
  try {
    const scanIds = store.selectedScans.map(s => s.scan_id)
    await store.bulkDeleteScans(scanIds)
    showDeleteConfirm.value = false
  } catch (e) {
    console.error('Failed to delete scans:', e)
  }
}

async function handleBulkArchive() {
  try {
    const scanIds = store.selectedScans.map(s => s.scan_id)
    await store.bulkArchiveScans(scanIds)
    showArchiveConfirm.value = false
  } catch (e) {
    console.error('Failed to archive scans:', e)
  }
}

// Track unsubscribe function
let unsubscribeCredentialStatus = null

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

  // Subscribe to credential status changes
  unsubscribeCredentialStatus = onCredentialStatusChange(() => {
    store.fetchCredentialStatus()
  })
})

onUnmounted(() => {
  store.stopAllPolling()
  // Unsubscribe from credential status changes
  if (unsubscribeCredentialStatus) {
    unsubscribeCredentialStatus()
  }
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

/* Status Cell with Progress */
.status-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.mini-progress {
  font-size: 0.75rem;
  color: var(--primary-color, #3b82f6);
  background-color: var(--primary-50, #eff6ff);
  padding: 0.125rem 0.375rem;
  border-radius: 0.25rem;
  font-weight: 500;
}

/* Bulk Actions Toolbar */
.bulk-actions-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--accent-primary-bg);
  border: 1px solid var(--accent-primary);
  border-radius: var(--radius-md);
  margin-bottom: var(--spacing-md);
}

.selection-count {
  font-weight: 500;
  color: var(--accent-primary);
}

.bulk-buttons {
  display: flex;
  gap: var(--spacing-sm);
}

.confirm-warning {
  color: var(--red-500);
  font-size: 0.875rem;
}

.confirm-info {
  color: var(--text-secondary);
  font-size: 0.875rem;
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
  margin-bottom: var(--spacing-sm);
}

/* Profile Provider Toggles */
.profile-provider-toggles {
  display: flex;
  gap: 0.5rem;
  margin-bottom: var(--spacing-md);
}

.profile-provider-btn {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.375rem 0.625rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.15s ease;
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-secondary);
  flex: 1;
  justify-content: center;
}

.profile-provider-btn:hover:not(.disabled) {
  border-color: var(--accent-primary);
  color: var(--text-primary);
}

.profile-provider-btn.active {
  border-color: var(--green-500);
  background: rgba(34, 197, 94, 0.1);
  color: var(--green-700);
}

.profile-provider-btn.disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.profile-provider-btn i:first-child {
  font-size: 0.875rem;
}

.profile-provider-btn .check-mark {
  font-size: 0.625rem;
  color: var(--green-500);
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

/* Error Details Dialog */
.error-details {
  padding: var(--spacing-sm);
}

.error-summary {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--red-50);
  border: 1px solid var(--red-200);
  border-radius: var(--radius-md);
  color: var(--red-700);
  margin-bottom: var(--spacing-md);
}

.error-icon {
  color: var(--red-500);
  font-size: 1.25rem;
  flex-shrink: 0;
}

.tool-status-list {
  margin-top: var(--spacing-md);
}

.tool-status-list h4 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.tool-status-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) 0;
  border-bottom: 1px solid var(--border-color);
}

.tool-status-item:last-child {
  border-bottom: none;
}

.tool-status-tag {
  min-width: 60px;
  text-align: center;
}

.tool-name {
  font-weight: 500;
  min-width: 100px;
}

.tool-error-msg {
  color: var(--text-secondary);
  font-size: 0.875rem;
  flex: 1;
  word-break: break-word;
}

.no-error-info {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  color: var(--text-secondary);
  padding: var(--spacing-md);
}

.loading-errors {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-xl);
  color: var(--text-secondary);
}

.cursor-pointer {
  cursor: pointer;
}

/* Provider Toggle Styles */
.provider-toggles {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
}

.provider-toggle-wrapper {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.25rem;
}

.provider-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.25rem;
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 0.15s ease;
  min-width: 120px;
  justify-content: center;
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--text-primary);
}

.provider-toggle:hover:not(.disabled) {
  border-color: var(--accent-primary);
  background: var(--accent-primary-bg);
}

.provider-toggle.active {
  border-color: var(--green-500);
  background: rgba(34, 197, 94, 0.1);
  color: var(--green-700);
}

.provider-toggle.active .check-icon {
  color: var(--green-500);
}

.provider-toggle.disabled {
  opacity: 0.5;
  cursor: not-allowed;
  background: var(--surface-100);
}

.provider-toggle i:first-child {
  font-size: 1.1rem;
}

.check-icon {
  margin-left: auto;
  font-size: 0.9rem;
}

.provider-status-hint {
  font-size: 0.7rem;
  color: var(--text-secondary);
  opacity: 0.8;
}

.helper-text {
  color: var(--text-secondary);
  font-size: 0.8rem;
  margin-top: 0.25rem;
}

/* IaC Scanning Card */
.iac-scanning-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-lg);
  background: linear-gradient(135deg, var(--bg-card) 0%, var(--accent-primary-bg) 100%);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  gap: var(--spacing-lg);
}

.iac-info {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-md);
  flex: 1;
}

.iac-icon {
  font-size: 2rem;
  color: var(--accent-primary);
  background: var(--bg-card);
  padding: var(--spacing-md);
  border-radius: var(--radius-md);
}

.iac-content h3 {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: 1rem;
  font-weight: 600;
}

.iac-content p {
  margin: 0;
  color: var(--text-secondary);
  font-size: 0.875rem;
}

@media (max-width: 768px) {
  .iac-scanning-card {
    flex-direction: column;
    text-align: center;
  }

  .iac-info {
    flex-direction: column;
    align-items: center;
  }
}
</style>
