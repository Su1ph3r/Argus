<template>
  <div class="settings-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Settings</h1>
        <p class="subtitle">
          Configure scan defaults, notifications, and data management
        </p>
      </div>
      <div class="header-actions">
        <Button
          label="Reset All"
          icon="pi pi-refresh"
          severity="secondary"
          :disabled="store.loading"
          @click="confirmReset"
        />
        <Button
          label="Save Changes"
          icon="pi pi-check"
          :loading="store.saving"
          :disabled="!hasChanges"
          @click="saveAllSettings"
        />
      </div>
    </div>

    <div
      v-if="store.loading"
      class="loading-container"
    >
      <ProgressSpinner />
      <span>Loading settings...</span>
    </div>

    <TabView
      v-else
      class="settings-tabs"
    >
      <!-- Scan Defaults Tab -->
      <TabPanel header="Scan Defaults">
        <div class="settings-section">
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-label">
                <h4>Default Scan Profile</h4>
                <p>Profile used when starting scans without explicit selection</p>
              </div>
              <Dropdown
                v-model="localSettings.default_scan_profile"
                :options="profileOptions"
                option-label="label"
                option-value="value"
                class="setting-input"
              />
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <h4>Default Regions</h4>
                <p>AWS regions to scan by default</p>
              </div>
              <MultiSelect
                v-model="localSettings.default_regions"
                :options="regionOptions"
                option-label="label"
                option-value="value"
                placeholder="Select regions"
                class="setting-input"
                :max-selected-labels="3"
              />
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <h4>Max Concurrent Scans</h4>
                <p>Maximum number of scans running simultaneously</p>
              </div>
              <InputNumber
                v-model="localSettings.max_concurrent_scans"
                :min="1"
                :max="10"
                show-buttons
                class="setting-input"
              />
            </div>
          </div>
        </div>
      </TabPanel>

      <!-- Notifications Tab -->
      <TabPanel header="Notifications">
        <div class="settings-section">
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-label">
                <h4>Enable Notifications</h4>
                <p>Receive notifications for scan events</p>
              </div>
              <InputSwitch v-model="localSettings.notifications_enabled" />
            </div>

            <div
              class="setting-item"
              :class="{ disabled: !localSettings.notifications_enabled }"
            >
              <div class="setting-label">
                <h4>Webhook URL</h4>
                <p>Webhook endpoint for notifications (Slack, Discord, etc.)</p>
              </div>
              <InputText
                v-model="localSettings.webhook_url"
                placeholder="https://..."
                class="setting-input"
                :disabled="!localSettings.notifications_enabled"
              />
            </div>

            <div
              class="setting-item"
              :class="{ disabled: !localSettings.notifications_enabled }"
            >
              <div class="setting-label">
                <h4>Webhook Events</h4>
                <p>Events that trigger webhook notifications</p>
              </div>
              <MultiSelect
                v-model="localSettings.webhook_events"
                :options="webhookEventOptions"
                option-label="label"
                option-value="value"
                placeholder="Select events"
                class="setting-input"
                :disabled="!localSettings.notifications_enabled"
              />
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <h4>Email Alerts</h4>
                <p>Enable email alerts for critical findings</p>
              </div>
              <InputSwitch v-model="localSettings.email_alerts_enabled" />
            </div>

            <div
              class="setting-item"
              :class="{ disabled: !localSettings.email_alerts_enabled }"
            >
              <div class="setting-label">
                <h4>Alert Email Address</h4>
                <p>Email address for security alerts</p>
              </div>
              <InputText
                v-model="localSettings.email_alert_address"
                placeholder="security@example.com"
                class="setting-input"
                :disabled="!localSettings.email_alerts_enabled"
              />
            </div>

            <div
              class="setting-item"
              :class="{ disabled: !localSettings.email_alerts_enabled }"
            >
              <div class="setting-label">
                <h4>Alert Threshold</h4>
                <p>Minimum severity for email alerts</p>
              </div>
              <Dropdown
                v-model="localSettings.email_alert_threshold"
                :options="thresholdOptions"
                option-label="label"
                option-value="value"
                class="setting-input"
                :disabled="!localSettings.email_alerts_enabled"
              />
            </div>
          </div>
        </div>
      </TabPanel>

      <!-- Data Management Tab -->
      <TabPanel header="Data Management">
        <div class="settings-section">
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-label">
                <h4>Auto Cleanup</h4>
                <p>Automatically delete scan results older than specified days</p>
              </div>
              <div class="input-with-suffix">
                <InputNumber
                  v-model="localSettings.auto_cleanup_days"
                  :min="1"
                  :max="365"
                  show-buttons
                />
                <span class="suffix">days</span>
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <h4>Default Export Format</h4>
                <p>Default format for exporting findings</p>
              </div>
              <Dropdown
                v-model="localSettings.export_format"
                :options="exportFormatOptions"
                option-label="label"
                option-value="value"
                class="setting-input"
              />
            </div>
          </div>

          <div class="data-actions">
            <h4>Data Operations</h4>
            <div class="action-buttons">
              <Button
                label="Export All Data"
                icon="pi pi-download"
                severity="secondary"
                @click="exportAllData"
              />
              <Button
                label="Clear Old Scans"
                icon="pi pi-trash"
                severity="warning"
                @click="confirmClearOldScans"
              />
              <Button
                label="Purge All Data"
                icon="pi pi-trash"
                severity="danger"
                @click="showPurgeDialog = true"
              />
            </div>
          </div>
        </div>
      </TabPanel>

      <!-- Display Tab -->
      <TabPanel header="Display">
        <div class="settings-section">
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-label">
                <h4>Theme</h4>
                <p>Application color theme</p>
              </div>
              <Dropdown
                v-model="localSettings.theme"
                :options="themeOptions"
                option-label="label"
                option-value="value"
                class="setting-input"
              />
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <h4>Findings Per Page</h4>
                <p>Number of findings shown per page in lists</p>
              </div>
              <Dropdown
                v-model="localSettings.findings_per_page"
                :options="pageeSizeOptions"
                option-label="label"
                option-value="value"
                class="setting-input"
              />
            </div>
          </div>
        </div>
      </TabPanel>
    </TabView>

    <!-- Confirmation Dialog -->
    <Dialog
      v-model:visible="showResetDialog"
      modal
      header="Reset Settings"
      :style="{ width: '400px' }"
    >
      <p>Are you sure you want to reset all settings to their default values?</p>
      <template #footer>
        <Button
          label="Cancel"
          text
          @click="showResetDialog = false"
        />
        <Button
          label="Reset"
          severity="danger"
          :loading="store.loading"
          @click="resetAllSettings"
        />
      </template>
    </Dialog>

    <!-- Clear Old Scans Dialog -->
    <Dialog
      v-model:visible="showClearOldDialog"
      modal
      header="Clear Old Scans"
      :style="{ width: '450px' }"
    >
      <div class="clear-old-info">
        <p>This will delete scans and related data older than <strong>{{ localSettings.auto_cleanup_days }} days</strong>.</p>
        <p class="info-note">
          You can adjust the number of days in the Auto Cleanup setting above.
        </p>
      </div>
      <template #footer>
        <Button
          label="Cancel"
          text
          @click="showClearOldDialog = false"
        />
        <Button
          label="Clear Old Scans"
          severity="warning"
          icon="pi pi-trash"
          :loading="clearingOld"
          @click="clearOldScans"
        />
      </template>
    </Dialog>

    <!-- Purge Database Dialog -->
    <Dialog
      v-model:visible="showPurgeDialog"
      modal
      header="Purge Database"
      :style="{ width: '500px' }"
    >
      <div class="purge-warning">
        <div class="warning-header">
          <i class="pi pi-exclamation-triangle" />
          <span>Warning: This action cannot be undone</span>
        </div>
        <p>This will permanently delete ALL scan data including:</p>
        <ul>
          <li>All scans and findings</li>
          <li>Attack paths and privilege escalation paths</li>
          <li>Public exposures and exposed credentials</li>
          <li>IMDS checks and Lambda analysis</li>
          <li>Severity overrides and tool execution history</li>
        </ul>
        <p>Credential verification status will also be reset.</p>
      </div>
      <template #footer>
        <Button
          label="Cancel"
          text
          @click="showPurgeDialog = false"
        />
        <Button
          label="Purge All Data"
          severity="danger"
          icon="pi pi-trash"
          :loading="purging"
          @click="purgeDatabase"
        />
      </template>
    </Dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useSettingsStore } from '../stores/settings'
import { useToast } from 'primevue/usetoast'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import MultiSelect from 'primevue/multiselect'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import InputSwitch from 'primevue/inputswitch'
import Dialog from 'primevue/dialog'
import ProgressSpinner from 'primevue/progressspinner'

const store = useSettingsStore()
const toast = useToast()

const showResetDialog = ref(false)
const showPurgeDialog = ref(false)
const showClearOldDialog = ref(false)
const purging = ref(false)
const clearingOld = ref(false)
const localSettings = ref({
  default_scan_profile: 'comprehensive',
  default_regions: ['us-east-1', 'us-west-2'],
  max_concurrent_scans: 3,
  auto_cleanup_days: 90,
  export_format: 'json',
  notifications_enabled: false,
  webhook_url: null,
  webhook_events: ['scan_complete', 'critical_finding'],
  email_alerts_enabled: false,
  email_alert_address: null,
  email_alert_threshold: 'critical',
  theme: 'dark',
  findings_per_page: 50,
})

const originalSettings = ref({})

const profileOptions = [
  { label: 'Quick Scan', value: 'quick' },
  { label: 'Comprehensive Scan', value: 'comprehensive' },
  { label: 'Compliance Only', value: 'compliance-only' },
]

const regionOptions = [
  { label: 'US East (N. Virginia)', value: 'us-east-1' },
  { label: 'US East (Ohio)', value: 'us-east-2' },
  { label: 'US West (N. California)', value: 'us-west-1' },
  { label: 'US West (Oregon)', value: 'us-west-2' },
  { label: 'EU (Ireland)', value: 'eu-west-1' },
  { label: 'EU (Frankfurt)', value: 'eu-central-1' },
  { label: 'Asia Pacific (Tokyo)', value: 'ap-northeast-1' },
  { label: 'Asia Pacific (Singapore)', value: 'ap-southeast-1' },
]

const webhookEventOptions = [
  { label: 'Scan Complete', value: 'scan_complete' },
  { label: 'Scan Failed', value: 'scan_failed' },
  { label: 'Critical Finding', value: 'critical_finding' },
  { label: 'High Finding', value: 'high_finding' },
]

const thresholdOptions = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
]

const exportFormatOptions = [
  { label: 'JSON', value: 'json' },
  { label: 'CSV', value: 'csv' },
  { label: 'Markdown', value: 'markdown' },
]

const themeOptions = [
  { label: 'Dark', value: 'dark' },
  { label: 'Light', value: 'light' },
]

const pageeSizeOptions = [
  { label: '25 per page', value: 25 },
  { label: '50 per page', value: 50 },
  { label: '100 per page', value: 100 },
]

const hasChanges = computed(() => {
  return JSON.stringify(localSettings.value) !== JSON.stringify(originalSettings.value)
})

async function loadSettings() {
  await store.fetchSettingsGrouped()

  // Map from store to local
  const s = store.settingsByCategory
  localSettings.value = {
    default_scan_profile: s.scans?.default_scan_profile || 'comprehensive',
    default_regions: s.scans?.default_regions || ['us-east-1', 'us-west-2'],
    max_concurrent_scans: s.scans?.max_concurrent_scans || 3,
    auto_cleanup_days: s.data?.auto_cleanup_days || 90,
    export_format: s.data?.export_format || 'json',
    notifications_enabled: s.notifications?.notifications_enabled || false,
    webhook_url: s.notifications?.webhook_url || null,
    webhook_events: s.notifications?.webhook_events || ['scan_complete', 'critical_finding'],
    email_alerts_enabled: s.notifications?.email_alerts_enabled || false,
    email_alert_address: s.notifications?.email_alert_address || null,
    email_alert_threshold: s.notifications?.email_alert_threshold || 'critical',
    theme: s.display?.theme || 'dark',
    findings_per_page: s.display?.findings_per_page || 50,
  }

  originalSettings.value = { ...localSettings.value }
}

async function saveAllSettings() {
  const updates = {}

  // Compare and collect changed settings
  for (const [key, value] of Object.entries(localSettings.value)) {
    if (JSON.stringify(value) !== JSON.stringify(originalSettings.value[key])) {
      updates[key] = value
    }
  }

  if (Object.keys(updates).length === 0) {
    return
  }

  try {
    const result = await store.updateMultipleSettings(updates)

    if (result.errors.length === 0) {
      toast.add({
        severity: 'success',
        summary: 'Settings Saved',
        detail: 'Your settings have been updated successfully',
        life: 3000,
      })
      originalSettings.value = { ...localSettings.value }
    } else {
      toast.add({
        severity: 'warn',
        summary: 'Partial Save',
        detail: `Some settings could not be saved: ${result.errors.map(e => e.key).join(', ')}`,
        life: 5000,
      })
    }
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Save Failed',
      detail: e.message,
      life: 5000,
    })
  }
}

function confirmReset() {
  showResetDialog.value = true
}

async function resetAllSettings() {
  try {
    await store.resetSettings()
    await loadSettings()
    showResetDialog.value = false
    toast.add({
      severity: 'success',
      summary: 'Settings Reset',
      detail: 'All settings have been reset to defaults',
      life: 3000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Reset Failed',
      detail: e.message,
      life: 5000,
    })
  }
}

function exportAllData() {
  window.open('/api/exports/json?include_remediation=true', '_blank')
}

function confirmClearOldScans() {
  showClearOldDialog.value = true
}

async function clearOldScans() {
  clearingOld.value = true
  try {
    const days = localSettings.value.auto_cleanup_days || 90
    const response = await fetch(`/api/database/clear-old?days=${days}&confirm=true`, {
      method: 'DELETE',
    })

    if (!response.ok) {
      const err = await response.json()
      throw new Error(err.detail || 'Failed to clear old scans')
    }

    const result = await response.json()

    toast.add({
      severity: 'success',
      summary: 'Scans Cleared',
      detail: `Removed ${result.scans_deleted || 0} scans older than ${days} days`,
      life: 5000,
    })

    showClearOldDialog.value = false
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Clear Failed',
      detail: e.message,
      life: 5000,
    })
  } finally {
    clearingOld.value = false
  }
}

async function purgeDatabase() {
  purging.value = true
  try {
    const response = await fetch('/api/database/purge?confirm=true', {
      method: 'DELETE',
    })

    if (!response.ok) {
      const err = await response.json()
      throw new Error(err.detail || 'Failed to purge database')
    }

    const result = await response.json()

    toast.add({
      severity: 'success',
      summary: 'Database Purged',
      detail: `Removed ${result.total_rows_deleted} records from ${result.tables_purged.length} tables`,
      life: 5000,
    })

    showPurgeDialog.value = false
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Purge Failed',
      detail: e.message,
      life: 5000,
    })
  } finally {
    purging.value = false
  }
}

onMounted(() => {
  loadSettings()
})
</script>

<style scoped>
.settings-view {
  max-width: 1000px;
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

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: var(--spacing-xl);
  color: var(--text-secondary);
  gap: var(--spacing-md);
}

.settings-tabs {
  background: var(--bg-card);
  border-radius: var(--radius-lg);
  border: 1px solid var(--border-color);
}

.settings-section {
  padding: var(--spacing-md);
}

.setting-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.setting-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  background: var(--bg-tertiary);
  border-radius: var(--radius-md);
  gap: var(--spacing-lg);
}

.setting-item.disabled {
  opacity: 0.5;
}

.setting-label {
  flex: 1;
}

.setting-label h4 {
  margin: 0;
  font-size: 0.9375rem;
  font-weight: 600;
}

.setting-label p {
  margin: var(--spacing-xs) 0 0 0;
  font-size: 0.8125rem;
  color: var(--text-secondary);
}

.setting-input {
  min-width: 250px;
}

.input-with-suffix {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.input-with-suffix .suffix {
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.data-actions {
  margin-top: var(--spacing-xl);
  padding: var(--spacing-md);
  background: var(--bg-tertiary);
  border-radius: var(--radius-md);
}

.data-actions h4 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: 0.9375rem;
  font-weight: 600;
}

.action-buttons {
  display: flex;
  gap: var(--spacing-md);
  flex-wrap: wrap;
}

@media (max-width: 768px) {
  .setting-item {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-md);
  }

  .setting-input {
    width: 100%;
    min-width: auto;
  }

  .header-actions {
    flex-direction: column;
  }
}

/* Purge Dialog */
.purge-warning {
  color: var(--text-color);
}

.purge-warning .warning-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--red-50);
  color: var(--red-700);
  border-radius: var(--radius-md);
  margin-bottom: 1rem;
  font-weight: 600;
}

.purge-warning .warning-header i {
  font-size: 1.25rem;
}

.purge-warning p {
  margin: 0.5rem 0;
}

.purge-warning ul {
  margin: 0.5rem 0;
  padding-left: 1.5rem;
}

.purge-warning li {
  margin: 0.25rem 0;
  color: var(--text-color-secondary);
}

/* Clear Old Scans Dialog */
.clear-old-info {
  color: var(--text-color);
}

.clear-old-info p {
  margin: 0.5rem 0;
}

.clear-old-info .info-note {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
  margin-top: 1rem;
}
</style>
