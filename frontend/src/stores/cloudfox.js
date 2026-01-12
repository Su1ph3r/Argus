import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useExecutionsStore } from './executions'

const API_BASE = '/api'

export const useCloudfoxStore = defineStore('cloudfox', () => {
  // State
  const results = ref([])
  const currentResult = ref(null)
  const summary = ref(null)
  const modules = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const currentExecution = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })
  const filters = ref({
    moduleName: null,
    findingCategory: null,
    cloudProvider: null,
    riskLevel: null,
  })

  // Actions
  async function fetchResults() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.moduleName) {
        params.append('module_name', filters.value.moduleName)
      }
      if (filters.value.findingCategory) {
        params.append('finding_category', filters.value.findingCategory)
      }
      if (filters.value.cloudProvider) {
        params.append('cloud_provider', filters.value.cloudProvider)
      }
      if (filters.value.riskLevel) {
        params.append('risk_level', filters.value.riskLevel)
      }

      const response = await fetch(`${API_BASE}/cloudfox?${params}`)
      if (!response.ok) throw new Error('Failed to fetch CloudFox results')

      const data = await response.json()
      results.value = data.results
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching CloudFox results:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/cloudfox/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function fetchModules() {
    try {
      const response = await fetch(`${API_BASE}/cloudfox/modules`)
      if (!response.ok) throw new Error('Failed to fetch modules')

      modules.value = await response.json()
      return modules.value
    } catch (e) {
      console.error('Error fetching modules:', e)
      return null
    }
  }

  async function runCloudfox(request) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/cloudfox/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      })

      if (!response.ok) throw new Error('Failed to run CloudFox')

      const result = await response.json()
      currentExecution.value = result

      // If execution started successfully, start polling for status
      if (result.status === 'running' && result.execution_id) {
        const executionsStore = useExecutionsStore()
        executionsStore.startPolling(result.execution_id, (execution) => {
          currentExecution.value = execution
          // Refresh results when execution completes
          if (execution.status === 'completed') {
            fetchResults()
            fetchSummary()
          }
        })
      }

      return result
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function stopCurrentExecution() {
    if (currentExecution.value?.execution_id) {
      const executionsStore = useExecutionsStore()
      await executionsStore.stopExecution(currentExecution.value.execution_id)
      currentExecution.value = null
    }
  }

  async function getExecutionLogs() {
    if (currentExecution.value?.execution_id) {
      const executionsStore = useExecutionsStore()
      return await executionsStore.fetchExecutionLogs(currentExecution.value.execution_id)
    }
    return null
  }

  function setFilters(newFilters) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchResults()
  }

  return {
    results,
    currentResult,
    summary,
    modules,
    loading,
    error,
    pagination,
    filters,
    currentExecution,
    fetchResults,
    fetchSummary,
    fetchModules,
    runCloudfox,
    stopCurrentExecution,
    getExecutionLogs,
    setFilters,
  }
})
