import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useExecutionsStore } from './executions'
import { useCredentialsStore } from './credentials'

const API_BASE = '/api'

export const useLambdaAnalysisStore = defineStore('lambdaAnalysis', () => {
  // State
  const analyses = ref([])
  const currentAnalysis = ref(null)
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
    region: null,
    runtime: null,
    riskLevel: null,
    analysisStatus: null,
    hasSecrets: null,
  })

  // Getters
  const riskyFunctions = computed(() =>
    analyses.value.filter(a => a.risk_score >= 50),
  )

  const functionsWithSecrets = computed(() =>
    analyses.value.filter(a =>
      a.secrets_found && a.secrets_found.length > 0,
    ),
  )

  // Actions
  async function fetchAnalyses() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.region) {
        params.append('region', filters.value.region)
      }
      if (filters.value.runtime) {
        params.append('runtime', filters.value.runtime)
      }
      if (filters.value.riskLevel) {
        params.append('risk_level', filters.value.riskLevel)
      }
      if (filters.value.analysisStatus) {
        params.append('analysis_status', filters.value.analysisStatus)
      }
      if (filters.value.hasSecrets !== null) {
        params.append('has_secrets', filters.value.hasSecrets)
      }

      const response = await fetch(`${API_BASE}/lambda-analysis?${params}`)
      if (!response.ok) throw new Error('Failed to fetch Lambda analyses')

      const data = await response.json()
      analyses.value = data.analyses
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching Lambda analyses:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchRisky(minRiskScore = 50) {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)
      params.append('min_risk_score', minRiskScore)

      const response = await fetch(`${API_BASE}/lambda-analysis/risky?${params}`)
      if (!response.ok) throw new Error('Failed to fetch risky functions')

      const data = await response.json()
      analyses.value = data.analyses
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchWithSecrets() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      const response = await fetch(`${API_BASE}/lambda-analysis/with-secrets?${params}`)
      if (!response.ok) throw new Error('Failed to fetch functions with secrets')

      const data = await response.json()
      analyses.value = data.analyses
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchAnalysis(analysisId) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/lambda-analysis/${analysisId}`)
      if (!response.ok) throw new Error('Failed to fetch analysis')

      currentAnalysis.value = await response.json()
      return currentAnalysis.value
    } catch (e) {
      error.value = e.message
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchFindings(analysisId) {
    try {
      const response = await fetch(`${API_BASE}/lambda-analysis/${analysisId}/findings`)
      if (!response.ok) throw new Error('Failed to fetch findings')

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/lambda-analysis/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function exportAnalysis(analysisId, format = 'markdown') {
    try {
      const response = await fetch(
        `${API_BASE}/lambda-analysis/${analysisId}/export?format=${format}`,
      )
      if (!response.ok) throw new Error('Export failed')

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function runAnalysis(request) {
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

      const response = await fetch(`${API_BASE}/lambda-analysis/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestWithCreds),
      })

      if (!response.ok) throw new Error('Failed to run Lambda analysis')

      const result = await response.json()
      currentExecution.value = result

      // If execution started successfully, start polling for status
      if (result.status === 'running' && result.execution_id) {
        const executionsStore = useExecutionsStore()
        executionsStore.startPolling(result.execution_id, (execution) => {
          currentExecution.value = execution
          // Refresh results when execution completes
          if (execution.status === 'completed') {
            fetchAnalyses()
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
    fetchAnalyses()
  }

  return {
    analyses,
    currentAnalysis,
    summary,
    loading,
    error,
    pagination,
    filters,
    currentExecution,
    riskyFunctions,
    functionsWithSecrets,
    fetchAnalyses,
    fetchRisky,
    fetchWithSecrets,
    fetchAnalysis,
    fetchFindings,
    fetchSummary,
    exportAnalysis,
    runAnalysis,
    stopCurrentExecution,
    getExecutionLogs,
    setFilters,
  }
})
