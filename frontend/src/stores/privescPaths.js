import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const usePrivescPathsStore = defineStore('privescPaths', () => {
  // State
  const paths = ref([])
  const currentPath = ref(null)
  const summary = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })
  const filters = ref({
    minRiskScore: null,
    escalationMethod: null,
    cloudProvider: null,
    exploitability: null,
    status: 'open',
  })

  // Getters
  const criticalPaths = computed(() =>
    paths.value.filter(p => p.risk_score >= 80),
  )

  const highRiskPaths = computed(() =>
    paths.value.filter(p => p.risk_score >= 60 && p.risk_score < 80),
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
      if (filters.value.escalationMethod) {
        params.append('escalation_method', filters.value.escalationMethod)
      }
      if (filters.value.cloudProvider) {
        params.append('cloud_provider', filters.value.cloudProvider)
      }
      if (filters.value.exploitability) {
        params.append('exploitability', filters.value.exploitability)
      }
      if (filters.value.status) {
        params.append('status', filters.value.status)
      }

      const response = await fetch(`${API_BASE}/privesc-paths?${params}`)
      if (!response.ok) throw new Error('Failed to fetch privesc paths')

      const data = await response.json()
      paths.value = data.paths
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching privesc paths:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchPath(pathId) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/privesc-paths/${pathId}`)
      if (!response.ok) throw new Error('Failed to fetch path')

      currentPath.value = await response.json()
      return currentPath.value
    } catch (e) {
      error.value = e.message
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/privesc-paths/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function exportPath(pathId, format = 'markdown') {
    try {
      const response = await fetch(
        `${API_BASE}/privesc-paths/${pathId}/export?format=${format}`,
      )
      if (!response.ok) throw new Error('Export failed')

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  function setFilters(newFilters) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchPaths()
  }

  return {
    paths,
    currentPath,
    summary,
    loading,
    error,
    pagination,
    filters,
    criticalPaths,
    highRiskPaths,
    fetchPaths,
    fetchPath,
    fetchSummary,
    exportPath,
    setFilters,
  }
})
