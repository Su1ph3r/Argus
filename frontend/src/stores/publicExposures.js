import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const usePublicExposuresStore = defineStore('publicExposures', () => {
  // State
  const exposures = ref([])
  const currentExposure = ref(null)
  const summary = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })
  const filters = ref({
    exposureType: null,
    riskLevel: null,
    cloudProvider: null,
    isInternetExposed: null,
    status: 'open',
  })

  // Getters
  const criticalExposures = computed(() =>
    exposures.value.filter(e => e.risk_level === 'critical'),
  )

  const internetExposedCount = computed(() =>
    exposures.value.filter(e => e.is_internet_exposed).length,
  )

  // Actions
  async function fetchExposures() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.exposureType) {
        params.append('exposure_type', filters.value.exposureType)
      }
      if (filters.value.riskLevel) {
        params.append('risk_level', filters.value.riskLevel)
      }
      if (filters.value.cloudProvider) {
        params.append('cloud_provider', filters.value.cloudProvider)
      }
      if (filters.value.isInternetExposed !== null) {
        params.append('is_internet_exposed', filters.value.isInternetExposed)
      }
      if (filters.value.status) {
        params.append('status', filters.value.status)
      }

      const response = await fetch(`${API_BASE}/public-exposures?${params}`)
      if (!response.ok) throw new Error('Failed to fetch public exposures')

      const data = await response.json()
      exposures.value = data.exposures
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching public exposures:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchExposure(exposureId) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/public-exposures/${exposureId}`)
      if (!response.ok) throw new Error('Failed to fetch exposure')

      currentExposure.value = await response.json()
      return currentExposure.value
    } catch (e) {
      error.value = e.message
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/public-exposures/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function updateStatus(exposureId, status) {
    try {
      const response = await fetch(
        `${API_BASE}/public-exposures/${exposureId}/status?status=${status}`,
        { method: 'PATCH' },
      )
      if (!response.ok) throw new Error('Failed to update status')

      await fetchExposures()
      return true
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  function setFilters(newFilters) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchExposures()
  }

  function clearFilters() {
    filters.value = {
      exposureType: null,
      riskLevel: null,
      cloudProvider: null,
      isInternetExposed: null,
      status: 'open',
    }
    pagination.value.page = 1
    fetchExposures()
  }

  return {
    exposures,
    currentExposure,
    summary,
    loading,
    error,
    pagination,
    filters,
    criticalExposures,
    internetExposedCount,
    fetchExposures,
    fetchExposure,
    fetchSummary,
    updateStatus,
    setFilters,
    clearFilters,
  }
})
