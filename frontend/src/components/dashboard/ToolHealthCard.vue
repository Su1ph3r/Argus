<template>
  <div class="tool-health-container">
    <div class="health-header">
      <h3>Tool Execution Health</h3>
      <div
        v-if="!loading && overallSuccessRate !== null"
        :class="['overall-badge', getHealthClass(overallSuccessRate)]"
      >
        {{ overallSuccessRate }}%
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <i class="pi pi-spin pi-spinner" />
      <span>Loading health data...</span>
    </div>

    <div v-else-if="error" class="error-state">
      <i class="pi pi-exclamation-circle" />
      <span>{{ error }}</span>
    </div>

    <div v-else-if="Object.keys(tools).length === 0" class="empty-state">
      <i class="pi pi-cog" />
      <span>No tool executions in the last {{ periodDays }} days</span>
    </div>

    <div v-else class="tools-grid">
      <div
        v-for="(tool, name) in tools"
        :key="name"
        class="tool-card"
      >
        <div class="tool-header">
          <span class="tool-name">{{ formatToolName(name) }}</span>
          <span :class="['success-rate', getHealthClass(tool.success_rate)]">
            {{ tool.success_rate }}%
          </span>
        </div>
        <div class="tool-stats">
          <div class="stat">
            <span class="stat-value">{{ tool.total_executions }}</span>
            <span class="stat-label">Total</span>
          </div>
          <div class="stat completed">
            <span class="stat-value">{{ tool.completed }}</span>
            <span class="stat-label">Passed</span>
          </div>
          <div class="stat failed">
            <span class="stat-value">{{ tool.failed }}</span>
            <span class="stat-label">Failed</span>
          </div>
        </div>
        <div v-if="tool.avg_duration_seconds" class="tool-duration">
          Avg: {{ formatDuration(tool.avg_duration_seconds) }}
        </div>
      </div>
    </div>

    <div class="health-footer">
      <span class="period-info">Last {{ periodDays }} days</span>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { apiClient } from '../../services/api'

const loading = ref(true)
const error = ref(null)
const tools = ref({})
const overallSuccessRate = ref(null)
const periodDays = ref(30)

const fetchHealth = async () => {
  loading.value = true
  error.value = null

  try {
    const response = await apiClient.get(`/executions/health/summary?days=${periodDays.value}`)
    tools.value = response.data.tools || {}
    overallSuccessRate.value = response.data.overall_success_rate
    periodDays.value = response.data.period_days
  } catch (err) {
    error.value = 'Failed to load health data'
    console.error('Error fetching health:', err)
  } finally {
    loading.value = false
  }
}

const formatToolName = (name) => {
  return name
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

const formatDuration = (seconds) => {
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${(seconds / 3600).toFixed(1)}h`
}

const getHealthClass = (rate) => {
  if (rate >= 90) return 'healthy'
  if (rate >= 70) return 'warning'
  return 'critical'
}

onMounted(() => {
  fetchHealth()
})
</script>

<style scoped>
.tool-health-container {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
}

.health-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.health-header h3 {
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
}

.overall-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 600;
}

.overall-badge.healthy {
  background: var(--severity-low-bg);
  color: var(--severity-low);
}

.overall-badge.warning {
  background: var(--severity-medium-bg);
  color: var(--severity-medium);
}

.overall-badge.critical {
  background: var(--severity-critical-bg);
  color: var(--severity-critical);
}

.tools-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: var(--spacing-md);
}

.tool-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: var(--spacing-md);
  transition: all 0.2s ease;
}

.tool-card:hover {
  border-color: var(--border-color-light);
}

.tool-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.tool-name {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--text-primary);
}

.success-rate {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: var(--radius-xs);
}

.success-rate.healthy {
  background: var(--severity-low-bg);
  color: var(--severity-low);
}

.success-rate.warning {
  background: var(--severity-medium-bg);
  color: var(--severity-medium);
}

.success-rate.critical {
  background: var(--severity-critical-bg);
  color: var(--severity-critical);
}

.tool-stats {
  display: flex;
  gap: var(--spacing-sm);
}

.stat {
  flex: 1;
  text-align: center;
}

.stat-value {
  display: block;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-primary);
}

.stat-label {
  display: block;
  font-size: 0.625rem;
  color: var(--text-muted);
  text-transform: uppercase;
}

.stat.completed .stat-value {
  color: var(--severity-low);
}

.stat.failed .stat-value {
  color: var(--severity-critical);
}

.tool-duration {
  font-size: 0.6875rem;
  color: var(--text-muted);
  margin-top: var(--spacing-sm);
  text-align: center;
}

.health-footer {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-sm);
  border-top: 1px solid var(--border-color);
}

.period-info {
  font-size: 0.75rem;
  color: var(--text-muted);
}

.loading-state,
.error-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-xl);
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.error-state {
  color: var(--severity-critical);
}
</style>
