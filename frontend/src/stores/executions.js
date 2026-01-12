import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const useExecutionsStore = defineStore('executions', () => {
  // State
  const executions = ref([])
  const currentExecution = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pollingIntervals = ref({})
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })

  // Actions
  async function fetchExecutions(toolName = null, status = null) {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (toolName) {
        params.append('tool_name', toolName)
      }
      if (status) {
        params.append('status', status)
      }

      const response = await fetch(`${API_BASE}/executions?${params}`)
      if (!response.ok) throw new Error('Failed to fetch executions')

      const data = await response.json()
      executions.value = data.executions
      pagination.value.total = data.total
      return data.executions
    } catch (e) {
      error.value = e.message
      console.error('Error fetching executions:', e)
      return []
    } finally {
      loading.value = false
    }
  }

  async function fetchExecution(executionId) {
    try {
      const response = await fetch(`${API_BASE}/executions/${executionId}`)
      if (!response.ok) throw new Error('Failed to fetch execution')

      const data = await response.json()
      currentExecution.value = data
      return data
    } catch (e) {
      console.error('Error fetching execution:', e)
      return null
    }
  }

  async function fetchExecutionLogs(executionId, tail = 100) {
    try {
      const response = await fetch(`${API_BASE}/executions/${executionId}/logs?tail=${tail}`)
      if (!response.ok) throw new Error('Failed to fetch logs')

      return await response.json()
    } catch (e) {
      console.error('Error fetching logs:', e)
      return null
    }
  }

  async function stopExecution(executionId) {
    try {
      const response = await fetch(`${API_BASE}/executions/${executionId}/stop`, {
        method: 'POST',
      })
      if (!response.ok) throw new Error('Failed to stop execution')

      // Stop polling if active
      stopPolling(executionId)

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function deleteExecution(executionId) {
    try {
      const response = await fetch(`${API_BASE}/executions/${executionId}`, {
        method: 'DELETE',
      })
      if (!response.ok) throw new Error('Failed to delete execution')

      // Stop polling if active
      stopPolling(executionId)

      // Remove from local state
      executions.value = executions.value.filter(e => e.execution_id !== executionId)

      return true
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function checkDockerStatus() {
    try {
      const response = await fetch(`${API_BASE}/executions/docker/status`)
      if (!response.ok) throw new Error('Failed to check Docker status')

      return await response.json()
    } catch (e) {
      console.error('Error checking Docker status:', e)
      return { docker_available: false, message: e.message }
    }
  }

  // Polling for execution status
  function startPolling(executionId, callback, interval = 3000) {
    // Don't start multiple pollers for the same execution
    if (pollingIntervals.value[executionId]) {
      return
    }

    const poll = async () => {
      const execution = await fetchExecution(executionId)

      if (execution) {
        // Update in local state
        const idx = executions.value.findIndex(e => e.execution_id === executionId)
        if (idx !== -1) {
          executions.value[idx] = execution
        }

        // Call callback
        if (callback) {
          callback(execution)
        }

        // Stop polling if execution is complete
        if (['completed', 'failed', 'cancelled'].includes(execution.status)) {
          stopPolling(executionId)
        }
      }
    }

    // Initial poll
    poll()

    // Set up interval
    pollingIntervals.value[executionId] = setInterval(poll, interval)
  }

  function stopPolling(executionId) {
    if (pollingIntervals.value[executionId]) {
      clearInterval(pollingIntervals.value[executionId])
      delete pollingIntervals.value[executionId]
    }
  }

  function stopAllPolling() {
    Object.keys(pollingIntervals.value).forEach(id => {
      stopPolling(id)
    })
  }

  // Computed
  const runningExecutions = computed(() =>
    executions.value.filter(e => e.status === 'running'),
  )

  const completedExecutions = computed(() =>
    executions.value.filter(e => e.status === 'completed'),
  )

  const failedExecutions = computed(() =>
    executions.value.filter(e => e.status === 'failed'),
  )

  return {
    executions,
    currentExecution,
    loading,
    error,
    pagination,
    runningExecutions,
    completedExecutions,
    failedExecutions,
    fetchExecutions,
    fetchExecution,
    fetchExecutionLogs,
    stopExecution,
    deleteExecution,
    checkDockerStatus,
    startPolling,
    stopPolling,
    stopAllPolling,
  }
})
