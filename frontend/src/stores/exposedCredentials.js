import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const useExposedCredentialsStore = defineStore('exposedCredentials', () => {
  // State
  const credentials = ref([])
  const currentCredential = ref(null)
  const summary = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })
  const filters = ref({
    credentialType: null,
    sourceType: null,
    cloudProvider: null,
    isActive: null,
    remediationStatus: null,
  })

  // Getters
  const activeCredentials = computed(() =>
    credentials.value.filter(c => c.is_active),
  )

  // Actions
  async function fetchCredentials() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.credentialType) {
        params.append('credential_type', filters.value.credentialType)
      }
      if (filters.value.sourceType) {
        params.append('source_type', filters.value.sourceType)
      }
      if (filters.value.cloudProvider) {
        params.append('cloud_provider', filters.value.cloudProvider)
      }
      if (filters.value.isActive !== null) {
        params.append('is_active', filters.value.isActive)
      }
      if (filters.value.remediationStatus) {
        params.append('remediation_status', filters.value.remediationStatus)
      }

      const response = await fetch(`${API_BASE}/exposed-credentials?${params}`)
      if (!response.ok) throw new Error('Failed to fetch exposed credentials')

      const data = await response.json()
      credentials.value = data.credentials
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching credentials:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchCredential(credentialId) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/exposed-credentials/${credentialId}`)
      if (!response.ok) throw new Error('Failed to fetch credential')

      currentCredential.value = await response.json()
      return currentCredential.value
    } catch (e) {
      error.value = e.message
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/exposed-credentials/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function updateRemediation(credentialId, status, notes) {
    try {
      const response = await fetch(
        `${API_BASE}/exposed-credentials/${credentialId}/remediation`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            remediation_status: status,
            remediation_notes: notes,
          }),
        },
      )
      if (!response.ok) throw new Error('Failed to update remediation')

      await fetchCredentials()
      return true
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  function setFilters(newFilters) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchCredentials()
  }

  return {
    credentials,
    currentCredential,
    summary,
    loading,
    error,
    pagination,
    filters,
    activeCredentials,
    fetchCredentials,
    fetchCredential,
    fetchSummary,
    updateRemediation,
    setFilters,
  }
})
