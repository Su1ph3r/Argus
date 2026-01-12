import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const useAssumedRolesStore = defineStore('assumedRoles', () => {
  // State
  const mappings = ref([])
  const currentMapping = ref(null)
  const summary = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pagination = ref({
    page: 1,
    pageSize: 50,
    total: 0,
  })
  const filters = ref({
    cloudProvider: null,
    sourcePrincipalType: null,
    isCrossAccount: null,
    riskLevel: null,
    neo4jSynced: null,
  })

  // Getters
  const crossAccountMappings = computed(() =>
    mappings.value.filter(m => m.is_cross_account),
  )

  // Actions
  async function fetchMappings() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.value.cloudProvider) {
        params.append('cloud_provider', filters.value.cloudProvider)
      }
      if (filters.value.sourcePrincipalType) {
        params.append('source_principal_type', filters.value.sourcePrincipalType)
      }
      if (filters.value.isCrossAccount !== null) {
        params.append('is_cross_account', filters.value.isCrossAccount)
      }
      if (filters.value.riskLevel) {
        params.append('risk_level', filters.value.riskLevel)
      }
      if (filters.value.neo4jSynced !== null) {
        params.append('neo4j_synced', filters.value.neo4jSynced)
      }

      const response = await fetch(`${API_BASE}/assumed-roles?${params}`)
      if (!response.ok) throw new Error('Failed to fetch assumed role mappings')

      const data = await response.json()
      mappings.value = data.mappings
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
      console.error('Error fetching mappings:', e)
    } finally {
      loading.value = false
    }
  }

  async function fetchCrossAccount() {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      const response = await fetch(`${API_BASE}/assumed-roles/cross-account?${params}`)
      if (!response.ok) throw new Error('Failed to fetch cross-account roles')

      const data = await response.json()
      mappings.value = data.mappings
      pagination.value.total = data.total
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchChains(minDepth = 2) {
    try {
      const response = await fetch(`${API_BASE}/assumed-roles/chains?min_depth=${minDepth}`)
      if (!response.ok) throw new Error('Failed to fetch chains')

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch(`${API_BASE}/assumed-roles/summary`)
      if (!response.ok) throw new Error('Failed to fetch summary')

      summary.value = await response.json()
      return summary.value
    } catch (e) {
      console.error('Error fetching summary:', e)
      return null
    }
  }

  async function syncToNeo4j(mappingIds, syncAll = false) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/assumed-roles/sync-neo4j`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mapping_ids: mappingIds,
          sync_all: syncAll,
        }),
      })

      if (!response.ok) throw new Error('Failed to sync to Neo4j')

      await fetchMappings()
      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function getNeo4jQuery(mappingId) {
    try {
      const response = await fetch(`${API_BASE}/assumed-roles/${mappingId}/neo4j-query`)
      if (!response.ok) throw new Error('Failed to get Neo4j query')

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  function setFilters(newFilters) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchMappings()
  }

  return {
    mappings,
    currentMapping,
    summary,
    loading,
    error,
    pagination,
    filters,
    crossAccountMappings,
    fetchMappings,
    fetchCrossAccount,
    fetchChains,
    fetchSummary,
    syncToNeo4j,
    getNeo4jQuery,
    setFilters,
  }
})
