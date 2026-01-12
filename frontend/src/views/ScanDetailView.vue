<template>
  <div class="scan-detail-view">
    <div class="page-header">
      <div class="header-content">
        <Button
          icon="pi pi-arrow-left"
          text
          class="back-btn"
          @click="$router.push('/scans')"
        />
        <div>
          <h1>Scan Details</h1>
          <p class="subtitle">
            {{ scan?.scan_id || 'Loading...' }}
          </p>
        </div>
      </div>
      <div
        v-if="scan"
        class="header-actions"
      >
        <Tag
          :severity="getStatusSeverity(scan.status)"
          :value="scan.status"
        />
        <Button
          v-if="scan.status === 'running'"
          label="Cancel Scan"
          icon="pi pi-stop"
          severity="danger"
          @click="cancelScan"
        />
      </div>
    </div>

    <div
      v-if="loading"
      class="loading-container"
    >
      <ProgressSpinner />
      <span>Loading scan details...</span>
    </div>

    <template v-else-if="scan">
      <!-- Scan Info -->
      <section class="section">
        <div class="info-grid">
          <div class="info-card">
            <div class="info-label">
              Profile
            </div>
            <div class="info-value">
              {{ scan.scan_type || scan.tool || 'N/A' }}
            </div>
          </div>
          <div class="info-card">
            <div class="info-label">
              Target
            </div>
            <div class="info-value">
              {{ scan.target || 'All resources' }}
            </div>
          </div>
          <div class="info-card">
            <div class="info-label">
              Started
            </div>
            <div class="info-value">
              {{ formatDate(scan.started_at) }}
            </div>
          </div>
          <div class="info-card">
            <div class="info-label">
              Completed
            </div>
            <div class="info-value">
              {{ scan.completed_at ? formatDate(scan.completed_at) : '-' }}
            </div>
          </div>
        </div>
      </section>

      <!-- Findings Summary -->
      <section
        v-if="scan.status === 'completed'"
        class="section"
      >
        <h2 class="section-title">
          Findings Summary
        </h2>
        <div class="findings-grid">
          <div class="finding-card critical">
            <div class="finding-count">
              {{ scan.critical_findings || 0 }}
            </div>
            <div class="finding-label">
              Critical
            </div>
          </div>
          <div class="finding-card high">
            <div class="finding-count">
              {{ scan.high_findings || 0 }}
            </div>
            <div class="finding-label">
              High
            </div>
          </div>
          <div class="finding-card medium">
            <div class="finding-count">
              {{ scan.medium_findings || 0 }}
            </div>
            <div class="finding-label">
              Medium
            </div>
          </div>
          <div class="finding-card low">
            <div class="finding-count">
              {{ scan.low_findings || 0 }}
            </div>
            <div class="finding-label">
              Low
            </div>
          </div>
        </div>

        <div class="findings-actions">
          <Button
            label="View All Findings"
            icon="pi pi-list"
            @click="viewFindings"
          />
        </div>
      </section>

      <!-- Running Status -->
      <section
        v-if="scan.status === 'running'"
        class="section"
      >
        <h2 class="section-title">
          Scan Progress
        </h2>
        <div class="progress-card">
          <ProgressBar mode="indeterminate" />
          <p>Scan is running. This may take several minutes depending on the profile.</p>
        </div>
      </section>

      <!-- Execution Logs -->
      <section
        v-if="logs"
        class="section"
      >
        <h2 class="section-title">
          Execution Logs
        </h2>
        <div class="logs-container">
          <pre>{{ logs }}</pre>
        </div>
      </section>
    </template>

    <div
      v-else
      class="empty-state"
    >
      <i class="pi pi-exclamation-circle" />
      <p>Scan not found</p>
      <Button
        label="Back to Scans"
        @click="$router.push('/scans')"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScansStore } from '../stores/scans'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import ProgressBar from 'primevue/progressbar'

const props = defineProps({
  id: {
    type: String,
    required: true,
  },
})

const route = useRoute()
const router = useRouter()
const store = useScansStore()

const scan = ref(null)
const logs = ref(null)
const loading = ref(true)

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
  return new Date(dateStr).toLocaleString()
}

async function loadScan() {
  loading.value = true
  try {
    scan.value = await store.fetchScan(props.id)

    if (scan.value?.status === 'running') {
      store.startPolling(props.id, (updatedScan) => {
        scan.value = updatedScan
      })
    }
  } catch (e) {
    console.error('Failed to load scan:', e)
  } finally {
    loading.value = false
  }
}

async function cancelScan() {
  try {
    await store.cancelScan(props.id)
    scan.value.status = 'cancelled'
  } catch (e) {
    console.error('Failed to cancel scan:', e)
  }
}

function viewFindings() {
  router.push({
    path: '/findings',
    query: { scan_id: props.id },
  })
}

onMounted(() => {
  loadScan()
})

onUnmounted(() => {
  store.stopPolling(props.id)
})
</script>

<style scoped>
.scan-detail-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.back-btn {
  color: var(--text-secondary);
}

.page-header h1 {
  font-size: 1.5rem;
  font-weight: 700;
  margin: 0;
}

.subtitle {
  color: var(--text-secondary);
  font-family: monospace;
  font-size: 0.875rem;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.section {
  margin-bottom: var(--spacing-xl);
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0 0 var(--spacing-md) 0;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: var(--spacing-xl);
  color: var(--text-secondary);
  gap: var(--spacing-md);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
}

@media (max-width: 768px) {
  .info-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

.info-card {
  padding: var(--spacing-md);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
}

.info-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  margin-bottom: var(--spacing-xs);
}

.info-value {
  font-size: 1rem;
  font-weight: 500;
}

.findings-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

@media (max-width: 768px) {
  .findings-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

.finding-card {
  padding: var(--spacing-lg);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  text-align: center;
  border-left: 4px solid;
}

.finding-card.critical {
  border-left-color: var(--red-500);
}

.finding-card.high {
  border-left-color: var(--orange-500);
}

.finding-card.medium {
  border-left-color: var(--yellow-500);
}

.finding-card.low {
  border-left-color: var(--green-500);
}

.finding-count {
  font-size: 2rem;
  font-weight: 700;
  line-height: 1;
}

.finding-label {
  font-size: 0.875rem;
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

.progress-card {
  padding: var(--spacing-lg);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
}

.progress-card p {
  margin-top: var(--spacing-md);
  color: var(--text-secondary);
}

.logs-container {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: var(--spacing-md);
  max-height: 400px;
  overflow: auto;
}

.logs-container pre {
  margin: 0;
  font-family: monospace;
  font-size: 0.8125rem;
  white-space: pre-wrap;
  word-break: break-word;
}

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
</style>
