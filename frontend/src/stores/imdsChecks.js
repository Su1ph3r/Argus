import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useExecutionsStore } from './executions'
import { useCredentialsStore } from './credentials'

const API_BASE = '/api'

export const useImdsChecksStore = defineStore('imdsChecks', () => {
  // State
  const checks = ref([])
  const currentCheck = ref(null)
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
    cloudProvider: null,
    region: null,
    imdsV1Enabled: null,
    ssrfVulnerable: null,
    riskLevel: null,
  })

  // Getters
  const vulnerableInstances = computed(() =>
    checks.value.filter(c =>
      c.imds_v1_enabled ||
      c.ssrf_vulnerable ||
      c.container_credential_exposure,
    ),
  )

  // Actions
  async function fetchChecks() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.cloudProvider) {
        params.append('cloud_provider', filters.value.cloudProvider)
      }
      if (filters.value.region) {
        params.append('region', filters.value.region)
      }
      if (filters.value.imdsV1Enabled !== null) {
        params.append('imds_v1_enabled', filters.value.imdsV1Enabled)
      }
      if (filters.value.ssrfVulnerable !== null) {
        params.append('ssrf_vulnerable', filters.value.ssrfVulnerable)
      }
      if (filters.value.riskLevel) {
        params.append('risk_level', filters.value.riskLevel)
      }

      const response = await fetch(`${API_BASE}/imds-checks?${params}`)
      if (!response.ok) throw new Error('Failed to fetch IMDS checks')

      const data = await response.json()
      checks.value = data.checks
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching IMDS checks:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchVulnerable() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      const response = await fetch(`${API_BASE}/imds-checks/vulnerable?${params}`)
      if (!response.ok) throw new Error('Failed to fetch vulnerable instances')

      const data = await response.json()
      checks.value = data.checks
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/imds-checks/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function updateRemediation(checkId, status) {
    try {
      const response = await fetch(
        `${API_BASE}/imds-checks/${checkId}/remediation?status=${status}`,
        { method: 'PATCH' },
      )
      if (!response.ok) throw new Error('Failed to update remediation')

      await fetchChecks()
      return true
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function runScan(request = {}) {
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

      const response = await fetch(`${API_BASE}/imds-checks/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestWithCreds),
      })

      if (!response.ok) throw new Error('Failed to run IMDS check')

      const result = await response.json()
      currentExecution.value = result

      // If execution started successfully, start polling for status
      if (result.status === 'running' && result.execution_id) {
        const executionsStore = useExecutionsStore()
        executionsStore.startPolling(result.execution_id, (execution) => {
          currentExecution.value = execution
          // Refresh results when execution completes
          if (execution.status === 'completed') {
            fetchChecks()
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
    fetchChecks()
  }

  return {
    checks,
    currentCheck,
    summary,
    loading,
    error,
    pagination,
    filters,
    currentExecution,
    vulnerableInstances,
    fetchChecks,
    fetchVulnerable,
    fetchSummary,
    updateRemediation,
    runScan,
    stopCurrentExecution,
    getExecutionLogs,
    setFilters,
  }
})
