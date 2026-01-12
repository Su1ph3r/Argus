import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const useAttackPathsStore = defineStore('attackPaths', () => {
  // State
  const paths = ref([])
  const currentPath = ref(null)
  const summary = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 20,
    total: 0,
  })
  const filters = ref({
    minRiskScore: null,
    maxRiskScore: null,
    exploitability: null,
    entryPointType: null,
    targetType: null,
  })

  // Getters
  const criticalPaths = computed(() =>
    paths.value.filter(p => p.risk_score >= 80),
  )

  const highRiskPaths = computed(() =>
    paths.value.filter(p => p.risk_score >= 60 && p.risk_score < 80),
  )

  const hasFilters = computed(() =>
    Object.values(filters.value).some(v => v !== null && v !== ''),
  )

  // Actions
  async function fetchPaths() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.minRiskScore !== null) {
        params.append('min_risk_score', filters.value.minRiskScore)
      }
      if (filters.value.maxRiskScore !== null) {
        params.append('max_risk_score', filters.value.maxRiskScore)
      }
      if (filters.value.exploitability) {
        params.append('exploitability', filters.value.exploitability)
      }
      if (filters.value.entryPointType) {
        params.append('entry_point_type', filters.value.entryPointType)
      }
      if (filters.value.targetType) {
        params.append('target_type', filters.value.targetType)
      }

      const response = await fetch(`${API_BASE}/attack-paths?${params}`)
      if (!response.ok) throw new Error('Failed to fetch attack paths')

      const data = await response.json()
      paths.value = data.paths
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching attack paths:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchPath(pathId) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/attack-paths/${pathId}`)
      if (!response.ok) throw new Error('Failed to fetch attack path')

      currentPath.value = await response.json()
      return currentPath.value
    } catch (e) {
      error.value = e.message
      console.error('Error fetching attack path:', e)
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/attack-paths/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function analyzePaths() {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/attack-paths/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ max_depth: 5 }),
      })

      if (!response.ok) throw new Error('Analysis failed')

      const result = await response.json()

      // Refresh the list
      await fetchPaths()
      await fetchSummary()

      return result
    } catch (e) {
      error.value = e.message
      console.error('Error analyzing paths:', e)
      throw e
    } finally {
      loading.value = false
    }
  }

  async function exportPath(pathId, format = 'markdown') {
    try {
      const response = await fetch(`${API_BASE}/attack-paths/${pathId}/export?format=${format}`)
      if (!response.ok) throw new Error('Export failed')

      return await response.json()
    } catch (e) {
      console.error('Error exporting path:', e)
      throw e
    }
  }

  async function deletePath(pathId) {
    try {
      const response = await fetch(`${API_BASE}/attack-paths/${pathId}`, {
        method: 'DELETE',
      })
      if (!response.ok) throw new Error('Delete failed')

      // Remove from local state
      paths.value = paths.value.filter(p => p.id !== pathId)
      return true
    } catch (e) {
      console.error('Error deleting path:', e)
      throw e
    }
  }

  function setPage(page) {
    pagination.value.page = page
    fetchPaths()
  }

  function setFilters(newFilters) {
    // Replace entire filters object to ensure all values are set
    filters.value = {
      minRiskScore: newFilters.minRiskScore,
      maxRiskScore: newFilters.maxRiskScore,
      exploitability: newFilters.exploitability,
      entryPointType: newFilters.entryPointType,
      targetType: newFilters.targetType,
    }
    pagination.value.page = 1
    fetchPaths()
  }

  function clearFilters() {
    filters.value = {
      minRiskScore: null,
      maxRiskScore: null,
      exploitability: null,
      entryPointType: null,
      targetType: null,
    }
    pagination.value.page = 1
    fetchPaths()
  }

  return {
    // State
    paths,
    currentPath,
    summary,
    loading,
    error,
    pagination,
    filters,
    // Getters
    criticalPaths,
    highRiskPaths,
    hasFilters,
    // Actions
    fetchPaths,
    fetchPath,
    fetchSummary,
    analyzePaths,
    exportPath,
    deletePath,
    setPage,
    setFilters,
    clearFilters,
  }
})
