import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { toast } from '../services/toast'

export const useRiskExceptionsStore = defineStore('riskExceptions', () => {
  // State
  const exceptions = ref([])
  const currentException = ref(null)
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(50)
  const loading = ref(false)
  const error = ref(null)

  // Filters
  const filters = ref({
    status: null,
    canonical_id: null,
  })

  // Computed
  const hasFilters = computed(() => {
    return Object.values(filters.value).some(v => v !== null && v !== '')
  })

  const totalPages = computed(() => {
    return Math.ceil(total.value / pageSize.value)
  })

  const activeExceptions = computed(() => {
    return exceptions.value.filter(e => e.status === 'active')
  })

  // Actions
  async function fetchExceptions() {
    loading.value = true
    error.value = null

    try {
      const params = {
        page: page.value,
        page_size: pageSize.value,
        ...filters.value,
      }

      // Remove null/empty filter values
      Object.keys(params).forEach(key => {
        if (params[key] === null || params[key] === '') {
          delete params[key]
        }
      })

      const response = await fetch(`/api/risk-exceptions?${new URLSearchParams(params)}`)
      if (!response.ok) throw new Error('Failed to fetch risk exceptions')

      const data = await response.json()
      exceptions.value = data.exceptions || []
      total.value = data.total || 0
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to load risk exceptions')
      exceptions.value = []
      total.value = 0
    } finally {
      loading.value = false
    }
  }

  async function createException(findingIds, justification, expirationDate = null) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch('/api/risk-exceptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_ids: findingIds,
          justification: justification,
          expiration_date: expirationDate,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || 'Failed to create risk exception')
      }

      const exception = await response.json()
      exceptions.value.unshift(exception)
      total.value += 1

      toast.success('Risk Accepted', 'Finding marked as accepted risk')
      return exception
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to accept risk')
      throw err
    } finally {
      loading.value = false
    }
  }

  async function revokeException(exceptionId) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`/api/risk-exceptions/${exceptionId}`, {
        method: 'DELETE',
      })

      if (!response.ok) throw new Error('Failed to revoke risk exception')

      const result = await response.json()

      // Update local state
      const index = exceptions.value.findIndex(e => e.exception_id === exceptionId)
      if (index !== -1) {
        exceptions.value[index].status = 'revoked'
      }

      toast.success('Exception Revoked', `${result.findings_reopened} findings re-opened`)
      return result
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to revoke exception')
      throw err
    } finally {
      loading.value = false
    }
  }

  async function checkFindingException(findingId) {
    try {
      const response = await fetch(`/api/risk-exceptions/check/${findingId}`)
      if (!response.ok) throw new Error('Failed to check exception status')

      return await response.json()
    } catch (err) {
      console.error('Failed to check exception status:', err)
      return { has_active_exception: false, exception: null }
    }
  }

  function setFilter(key, value) {
    filters.value[key] = value
    page.value = 1
  }

  function clearFilters() {
    filters.value = {
      status: null,
      canonical_id: null,
    }
    page.value = 1
  }

  function setPage(newPage) {
    page.value = newPage
  }

  return {
    // State
    exceptions,
    currentException,
    total,
    page,
    pageSize,
    loading,
    error,
    filters,

    // Computed
    hasFilters,
    totalPages,
    activeExceptions,

    // Actions
    fetchExceptions,
    createException,
    revokeException,
    checkFindingException,
    setFilter,
    clearFilters,
    setPage,
  }
})
