import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const useSeverityOverridesStore = defineStore('severityOverrides', () => {
  // State
  const overrides = ref([])
  const currentOverride = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })
  const filters = ref({
    approvalStatus: null,
  })

  // Getters
  const pendingOverrides = computed(() =>
    overrides.value.filter(o => o.approval_status === 'pending'),
  )

  // Actions
  async function fetchOverrides() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.approvalStatus) {
        params.append('approval_status', filters.value.approvalStatus)
      }

      const response = await fetch(`${API_BASE}/severity-overrides?${params}`)
      if (!response.ok) throw new Error('Failed to fetch overrides')

      const data = await response.json()
      overrides.value = data.overrides
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching overrides:', e)
    } finally {
      loading.value = false
    }
  }

  async function createOverride(override) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/severity-overrides`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(override),
      })

      if (!response.ok) {
        const err = await response.json()
        throw new Error(err.detail || 'Failed to create override')
      }

      await fetchOverrides()
      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function approveOverride(overrideId, approved, approvedBy, notes) {
    try {
      const response = await fetch(
        `${API_BASE}/severity-overrides/${overrideId}/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            approved,
            approved_by: approvedBy,
            notes,
          }),
        },
      )

      if (!response.ok) throw new Error('Failed to process approval')

      await fetchOverrides()
      return true
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function deleteOverride(overrideId) {
    try {
      const response = await fetch(
        `${API_BASE}/severity-overrides/${overrideId}`,
        { method: 'DELETE' },
      )

      if (!response.ok) throw new Error('Failed to delete override')

      overrides.value = overrides.value.filter(o => o.id !== overrideId)
      return true
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function getOverrideByFinding(findingId) {
    try {
      const response = await fetch(`${API_BASE}/severity-overrides/by-finding/${findingId}`)
      if (response.status === 404) return null
      if (!response.ok) throw new Error('Failed to fetch override')

      return await response.json()
    } catch (e) {
      return null
    }
  }

  return {
    overrides,
    currentOverride,
    loading,
    error,
    pagination,
    filters,
    pendingOverrides,
    fetchOverrides,
    createOverride,
    approveOverride,
    deleteOverride,
    getOverrideByFinding,
  }
})
