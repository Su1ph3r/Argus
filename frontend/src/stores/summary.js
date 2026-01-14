import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../services/api'
import { toast } from '../services/toast'

export const useSummaryStore = defineStore('summary', () => {
  // State
  const summary = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const lastUpdated = ref(null)

  // Computed
  const totalFindings = computed(() => summary.value?.total || 0)
  const criticalCount = computed(() => summary.value?.critical || 0)
  const highCount = computed(() => summary.value?.high || 0)
  const mediumCount = computed(() => summary.value?.medium || 0)
  const lowCount = computed(() => summary.value?.low || 0)
  const infoCount = computed(() => summary.value?.info || 0)

  const severityData = computed(() => {
    if (!summary.value) return []
    return [
      { label: 'Critical', value: summary.value.critical || 0, color: '#e74c3c' },
      { label: 'High', value: summary.value.high || 0, color: '#e67e22' },
      { label: 'Medium', value: summary.value.medium || 0, color: '#f1c40f' },
      { label: 'Low', value: summary.value.low || 0, color: '#27ae60' },
      { label: 'Info', value: summary.value.info || 0, color: '#3498db' },
    ].filter(item => item.value > 0)
  })

  const byProvider = computed(() => {
    if (!summary.value?.by_provider) return []
    return Object.entries(summary.value.by_provider).map(([name, value]) => ({
      label: name,
      value,
    }))
  })

  const byTool = computed(() => {
    if (!summary.value?.by_tool) return []
    return Object.entries(summary.value.by_tool).map(([name, value]) => ({
      label: name,
      value,
    }))
  })

  // Actions
  async function fetchSummary() {
    loading.value = true
    error.value = null

    try {
      summary.value = await api.getSummary()
      lastUpdated.value = new Date()
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to load summary')
      summary.value = null
    } finally {
      loading.value = false
    }
  }

  function startAutoRefresh(intervalMs = 30000) {
    fetchSummary()
    return setInterval(fetchSummary, intervalMs)
  }

  return {
    // State
    summary,
    loading,
    error,
    lastUpdated,

    // Computed
    totalFindings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    severityData,
    byProvider,
    byTool,

    // Actions
    fetchSummary,
    startAutoRefresh,
  }
})
