import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useExecutionsStore } from './executions'
import { useCredentialsStore } from './credentials'

const API_BASE = '/api'

export const useEnumerateIamStore = defineStore('enumerateIam', () => {
  // State
  const results = ref([])
  const currentResult = ref(null)
  const summary = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const currentExecution = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })
  const filters = ref({
    principalType: null,
    privescCapable: null,
    adminCapable: null,
  })

  // Getters
  const highRiskPrincipals = computed(() =>
    results.value.filter(r =>
      r.privesc_capable || r.admin_capable || r.data_access_capable,
    ),
  )

  // Actions
  async function fetchResults() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.principalType) {
        params.append('principal_type', filters.value.principalType)
      }
      if (filters.value.privescCapable !== null) {
        params.append('privesc_capable', filters.value.privescCapable)
      }
      if (filters.value.adminCapable !== null) {
        params.append('admin_capable', filters.value.adminCapable)
      }

      const response = await fetch(`${API_BASE}/enumerate-iam?${params}`)
      if (!response.ok) throw new Error('Failed to fetch enumerate-iam results')

      const data = await response.json()
      results.value = data.results
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching enumerate-iam results:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchHighRisk() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      const response = await fetch(`${API_BASE}/enumerate-iam/high-risk?${params}`)
      if (!response.ok) throw new Error('Failed to fetch high-risk principals')

      const data = await response.json()
      results.value = data.results
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/enumerate-iam/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function fetchPermissions(resultId) {
    try {
      const response = await fetch(`${API_BASE}/enumerate-iam/${resultId}/permissions`)
      if (!response.ok) throw new Error('Failed to fetch permissions')

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function runEnumeration(request) {
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
      }

      const response = await fetch(`${API_BASE}/enumerate-iam/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestWithCreds),
      })

      if (!response.ok) throw new Error('Failed to run enumerate-iam')

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
    loading,
    error,
    pagination,
    filters,
    currentExecution,
    highRiskPrincipals,
    fetchResults,
    fetchHighRisk,
    fetchSummary,
    fetchPermissions,
    runEnumeration,
    stopCurrentExecution,
    getExecutionLogs,
    setFilters,
  }
})
