import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useExecutionsStore } from './executions'
import { useCredentialsStore } from './credentials'

const API_BASE = '/api'

export const usePacuStore = defineStore('pacu', () => {
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
    moduleCategory: null,
    executionStatus: null,
    sessionName: null,
  })

  // Getters
  const successfulExecutions = computed(() =>
    results.value.filter(r => r.execution_status === 'success'),
  )

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
      if (filters.value.moduleCategory) {
        params.append('module_category', filters.value.moduleCategory)
      }
      if (filters.value.executionStatus) {
        params.append('execution_status', filters.value.executionStatus)
      }
      if (filters.value.sessionName) {
        params.append('session_name', filters.value.sessionName)
      }

      const response = await fetch(`${API_BASE}/pacu?${params}`)
      if (!response.ok) throw new Error('Failed to fetch Pacu results')

      const data = await response.json()
      results.value = data.results
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching Pacu results:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/pacu/summary`)
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
      const response = await fetch(`${API_BASE}/pacu/modules`)
      if (!response.ok) throw new Error('Failed to fetch modules')

      modules.value = await response.json()
      return modules.value
    } catch (e) {
      console.error('Error fetching modules:', e)
      return null
    }
  }

  async function runModule(request) {
    loading.value = true
    error.value = null

    try {
      // Get AWS credentials from session
      const credentialsStore = useCredentialsStore()
      const awsCreds = credentialsStore.getSessionCredentials('aws')

      // Add credentials to request if available
      const requestWithCreds = { ...request }
      if (awsCreds) {
        requestWithCreds.access_key = awsCreds.access_key_id
        requestWithCreds.secret_key = awsCreds.secret_access_key
        if (awsCreds.session_token) {
          requestWithCreds.session_token = awsCreds.session_token
        }
        if (awsCreds.region) {
          requestWithCreds.region = awsCreds.region
        }
      }

      const response = await fetch(`${API_BASE}/pacu/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestWithCreds),
      })

      if (!response.ok) throw new Error('Failed to run Pacu module')

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
    successfulExecutions,
    fetchResults,
    fetchSummary,
    fetchModules,
    runModule,
    stopCurrentExecution,
    getExecutionLogs,
    setFilters,
  }
})
