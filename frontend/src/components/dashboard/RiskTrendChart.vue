<template>
  <div class="risk-trend-container">
    <div class="trend-header">
      <h3>Finding Trend ({{ days }} days)</h3>
      <div class="trend-controls">
        <select v-model="days" @change="fetchTrend" class="days-select">
          <option :value="7">7 days</option>
          <option :value="14">14 days</option>
          <option :value="30">30 days</option>
          <option :value="90">90 days</option>
        </select>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <i class="pi pi-spin pi-spinner" />
      <span>Loading trend data...</span>
    </div>

    <div v-else-if="error" class="error-state">
      <i class="pi pi-exclamation-circle" />
      <span>{{ error }}</span>
    </div>

    <div v-else class="trend-chart">
      <div class="chart-area">
        <div
          v-for="(point, index) in trendData"
          :key="point.date"
          class="chart-bar-group"
        >
          <div class="bar-stack">
            <div
              v-if="point.critical > 0"
              class="bar-segment critical"
              :style="{ height: getBarHeight(point.critical) + 'px' }"
              :title="`Critical: ${point.critical}`"
            />
            <div
              v-if="point.high > 0"
              class="bar-segment high"
              :style="{ height: getBarHeight(point.high) + 'px' }"
              :title="`High: ${point.high}`"
            />
            <div
              v-if="point.medium > 0"
              class="bar-segment medium"
              :style="{ height: getBarHeight(point.medium) + 'px' }"
              :title="`Medium: ${point.medium}`"
            />
            <div
              v-if="point.low > 0"
              class="bar-segment low"
              :style="{ height: getBarHeight(point.low) + 'px' }"
              :title="`Low: ${point.low}`"
            />
          </div>
          <div class="bar-label">{{ formatDate(point.date) }}</div>
        </div>
      </div>

      <div class="chart-legend">
        <div class="legend-item">
          <span class="legend-color critical" />
          <span>Critical</span>
        </div>
        <div class="legend-item">
          <span class="legend-color high" />
          <span>High</span>
        </div>
        <div class="legend-item">
          <span class="legend-color medium" />
          <span>Medium</span>
        </div>
        <div class="legend-item">
          <span class="legend-color low" />
          <span>Low</span>
        </div>
      </div>
    </div>

    <div v-if="!loading && !error && trendData.length === 0" class="empty-state">
      <i class="pi pi-chart-line" />
      <span>No trend data available for the selected period</span>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { apiClient } from '../../services/api'

const days = ref(30)
const loading = ref(true)
const error = ref(null)
const trendData = ref([])
const maxValue = ref(100)

const fetchTrend = async () => {
  loading.value = true
  error.value = null

  try {
    const response = await apiClient.get(`/findings/trend?days=${days.value}`)
    trendData.value = response.data.trend || []

    // Calculate max value for scaling
    maxValue.value = Math.max(
      10,
      ...trendData.value.map(d => d.total || 0)
    )
  } catch (err) {
    error.value = 'Failed to load trend data'
    console.error('Error fetching trend:', err)
  } finally {
    loading.value = false
  }
}

const getBarHeight = (value) => {
  const maxHeight = 120
  return Math.max(2, (value / maxValue.value) * maxHeight)
}

const formatDate = (dateStr) => {
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

onMounted(() => {
  fetchTrend()
})
</script>

<style scoped>
.risk-trend-container {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
}

.trend-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.trend-header h3 {
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
}

.days-select {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
  background: var(--bg-card);
  color: var(--text-primary);
  font-size: 0.75rem;
}

.trend-chart {
  min-height: 180px;
}

.chart-area {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 4px;
  height: 140px;
  padding-bottom: var(--spacing-sm);
  border-bottom: 1px solid var(--border-color);
}

.chart-bar-group {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 0;
}

.bar-stack {
  display: flex;
  flex-direction: column-reverse;
  width: 100%;
  max-width: 24px;
}

.bar-segment {
  width: 100%;
  min-height: 2px;
  border-radius: 2px 2px 0 0;
  transition: all 0.2s ease;
}

.bar-segment:hover {
  opacity: 0.8;
}

.bar-segment.critical {
  background: var(--severity-critical);
}

.bar-segment.high {
  background: var(--severity-high);
}

.bar-segment.medium {
  background: var(--severity-medium);
}

.bar-segment.low {
  background: var(--severity-low);
}

.bar-label {
  font-size: 0.625rem;
  color: var(--text-muted);
  margin-top: var(--spacing-xs);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.chart-legend {
  display: flex;
  gap: var(--spacing-md);
  margin-top: var(--spacing-md);
  flex-wrap: wrap;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.legend-color {
  width: 10px;
  height: 10px;
  border-radius: 2px;
}

.legend-color.critical {
  background: var(--severity-critical);
}

.legend-color.high {
  background: var(--severity-high);
}

.legend-color.medium {
  background: var(--severity-medium);
}

.legend-color.low {
  background: var(--severity-low);
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
