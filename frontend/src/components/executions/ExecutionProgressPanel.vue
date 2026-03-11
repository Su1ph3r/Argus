<template>
  <div
    v-if="execution"
    class="execution-progress-panel"
    :class="statusClass"
  >
    <div class="execution-header">
      <div class="execution-info">
        <i
          :class="statusIcon"
          class="execution-icon"
        />
        <span class="execution-title">{{ statusTitle }}</span>
      </div>
      <div class="execution-meta">
        <span
          v-if="execution.execution_id"
          class="execution-id"
        >
          ID: {{ execution.execution_id }}
        </span>
      </div>
    </div>

    <div
      v-if="isRunning"
      class="execution-progress"
    >
      <p class="progress-description">
        {{ description }}
      </p>
      <ProgressBar
        mode="indeterminate"
        class="progress-bar"
      />
    </div>

    <div
      v-if="execution.error"
      class="execution-error"
    >
      {{ execution.error }}
    </div>

    <div
      v-if="logs"
      class="execution-logs"
    >
      <pre>{{ logs }}</pre>
    </div>

    <!-- Slot for tool-specific stats/content -->
    <slot name="stats" />

    <div
      v-if="!isRunning"
      class="execution-actions"
    >
      <Button
        label="Dismiss"
        text
        size="small"
        @click="$emit('dismiss')"
      />
      <Button
        v-if="showViewResultsButton"
        :label="viewResultsLabel"
        size="small"
        @click="$emit('view-results')"
      />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import Button from 'primevue/button'
import ProgressBar from 'primevue/progressbar'

const props = defineProps({
  execution: {
    type: Object,
    default: null,
  },
  toolName: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    default: 'Execution in progress. This may take several minutes.',
  },
  logs: {
    type: String,
    default: null,
  },
  viewResultsLabel: {
    type: String,
    default: 'View Results',
  },
  showViewResultsOnFailed: {
    type: Boolean,
    default: false,
  },
})

defineEmits(['dismiss', 'view-results'])

const statusTitles = {
  running: 'running...',
  completed: 'completed',
  failed: 'failed',
  pending: 'pending',
}

const statusIcons = {
  running: 'pi pi-spin pi-spinner',
  completed: 'pi pi-check-circle',
  failed: 'pi pi-times-circle',
  pending: 'pi pi-clock',
}

const isRunning = computed(() => props.execution?.status === 'running')

const statusClass = computed(() => ({
  'status-running': props.execution?.status === 'running',
  'status-completed': props.execution?.status === 'completed',
  'status-failed': props.execution?.status === 'failed',
  'status-pending': props.execution?.status === 'pending',
}))

const statusIcon = computed(() =>
  statusIcons[props.execution?.status] || 'pi pi-info-circle',
)

const statusTitle = computed(() => {
  const statusText = statusTitles[props.execution?.status] || props.execution?.status
  return `${props.toolName} ${statusText}`
})

const showViewResultsButton = computed(() => {
  const status = props.execution?.status
  if (status === 'completed') return true
  if (status === 'failed' && props.showViewResultsOnFailed) return true
  return false
})
</script>

<style scoped>
.execution-progress-panel {
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 1.5rem;
  background: var(--surface-card);
  border-left: 4px solid var(--blue-500);
}

.execution-progress-panel.status-running {
  border-left-color: var(--blue-500);
  background: rgba(59, 130, 246, 0.1);
}

.execution-progress-panel.status-completed {
  border-left-color: var(--green-500);
  background: rgba(34, 197, 94, 0.1);
}

.execution-progress-panel.status-failed {
  border-left-color: var(--red-500);
  background: rgba(239, 68, 68, 0.1);
}

.execution-progress-panel.status-pending {
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

.execution-icon {
  font-size: 1.25rem;
}

.execution-title {
  font-weight: 600;
  color: var(--text-color);
}

.execution-id {
  font-family: monospace;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.execution-progress {
  margin-top: 0.75rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.execution-progress .progress-description {
  margin: 0 0 0.75rem 0;
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.execution-progress .progress-bar {
  height: 6px;
}

.execution-error {
  margin-top: 0.5rem;
  padding: 0.75rem;
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 4px;
  color: var(--severity-critical);
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
</style>
