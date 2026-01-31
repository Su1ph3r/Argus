<template>
  <Dialog
    v-model:visible="visible"
    modal
    :closable="!isRunning"
    :close-on-escape="!isRunning"
    header="Attack Path Analysis"
    :style="{ width: '450px' }"
    class="analysis-progress-modal"
  >
    <div class="modal-content">
      <!-- Running State -->
      <div
        v-if="isRunning"
        class="progress-state"
      >
        <ProgressSpinner style="width: 48px; height: 48px" />
        <h4>Analysis in Progress</h4>
        <p>Discovering attack paths from security findings...</p>

        <div
          v-if="job?.progress"
          class="progress-bar"
        >
          <ProgressBar :value="job.progress" />
          <span class="progress-text">{{ job.progress }}% complete</span>
        </div>

        <div class="status-info">
          <span class="status-badge running">
            <i class="pi pi-spin pi-spinner" />
            {{ job?.status || 'Running' }}
          </span>
          <span
            v-if="job?.started_at"
            class="elapsed-time"
          >
            Started {{ formatTimeAgo(job.started_at) }}
          </span>
        </div>
      </div>

      <!-- Completed State -->
      <div
        v-else-if="isCompleted"
        class="completed-state"
      >
        <i class="pi pi-check-circle success-icon" />
        <h4>Analysis Complete</h4>

        <div
          v-if="job?.result_summary"
          class="results-summary"
        >
          <div class="result-stat">
            <span class="stat-value">{{ job.result_summary.total_paths || 0 }}</span>
            <span class="stat-label">Attack Paths Found</span>
          </div>
          <div class="result-stat">
            <span class="stat-value">{{ job.result_summary.critical_paths || 0 }}</span>
            <span class="stat-label">Critical Paths</span>
          </div>
          <div class="result-stat">
            <span class="stat-value">{{ job.result_summary.high_risk_paths || 0 }}</span>
            <span class="stat-label">High Risk Paths</span>
          </div>
        </div>

        <div
          v-if="job?.completed_at"
          class="completion-info"
        >
          Completed {{ formatTimeAgo(job.completed_at) }}
        </div>
      </div>

      <!-- Failed State -->
      <div
        v-else-if="isFailed"
        class="failed-state"
      >
        <i class="pi pi-times-circle error-icon" />
        <h4>Analysis Failed</h4>
        <p class="error-message">
          {{ job?.error_message || 'Unknown error occurred' }}
        </p>

        <Button
          label="Retry Analysis"
          severity="secondary"
          @click="$emit('retry')"
        />
      </div>

      <!-- Idle State -->
      <div
        v-else
        class="idle-state"
      >
        <i class="pi pi-search" />
        <h4>Start Attack Path Analysis</h4>
        <p>Analyze security findings to discover potential attack paths and privilege escalation routes.</p>

        <Button
          label="Start Analysis"
          :loading="starting"
          @click="$emit('start')"
        />
      </div>
    </div>

    <template #footer>
      <div
        v-if="isCompleted"
        class="footer-actions"
      >
        <Button
          label="Close"
          severity="secondary"
          @click="close"
        />
        <Button
          label="View Attack Paths"
          @click="$emit('view-paths')"
        />
      </div>
      <div
        v-else-if="isRunning"
        class="footer-actions"
      >
        <Button
          label="Run in Background"
          severity="secondary"
          @click="close"
        />
      </div>
    </template>
  </Dialog>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  modelValue: {
    type: Boolean,
    default: false,
  },
  job: {
    type: Object,
    default: null,
  },
  starting: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['update:modelValue', 'start', 'retry', 'view-paths'])

// Computed
const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

const isRunning = computed(() => {
  return props.job?.status === 'pending' || props.job?.status === 'running'
})

const isCompleted = computed(() => {
  return props.job?.status === 'completed'
})

const isFailed = computed(() => {
  return props.job?.status === 'failed'
})

// Methods
function close() {
  visible.value = false
}

function formatTimeAgo(dateString) {
  if (!dateString) return ''

  const date = new Date(dateString)
  const now = new Date()
  const seconds = Math.floor((now - date) / 1000)

  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`
  return `${Math.floor(seconds / 86400)} days ago`
}
</script>

<style scoped>
.analysis-progress-modal .modal-content {
  padding: 1.5rem 0;
}

.progress-state,
.completed-state,
.failed-state,
.idle-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 1rem;
}

.progress-state h4,
.completed-state h4,
.failed-state h4,
.idle-state h4 {
  margin: 0;
}

.progress-state p,
.failed-state p,
.idle-state p {
  margin: 0;
  color: var(--text-color-secondary);
}

.progress-bar {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.progress-text {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.status-info {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.status-badge {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.375rem 0.75rem;
  border-radius: 20px;
  font-size: 0.875rem;
}

.status-badge.running {
  background: var(--blue-100);
  color: var(--blue-700);
}

.elapsed-time {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.success-icon {
  font-size: 3rem;
  color: var(--green-500);
}

.error-icon {
  font-size: 3rem;
  color: var(--red-500);
}

.results-summary {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  width: 100%;
  margin: 1rem 0;
}

.result-stat {
  padding: 1rem;
  background: var(--surface-100);
  border-radius: 8px;
}

.stat-value {
  display: block;
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary-color);
}

.stat-label {
  display: block;
  font-size: 0.75rem;
  color: var(--text-color-secondary);
}

.completion-info {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.error-message {
  padding: 0.75rem;
  background: var(--red-50);
  border-radius: 6px;
  color: var(--red-700);
  width: 100%;
}

.footer-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
}
</style>
