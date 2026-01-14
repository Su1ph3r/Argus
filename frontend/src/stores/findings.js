import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../services/api'
import { toast } from '../services/toast'

export const useFindingsStore = defineStore('findings', () => {
  // State
  const findings = ref([])
  const currentFinding = ref(null)
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(50)
  const loading = ref(false)
  const error = ref(null)

  // Sort state
  const sortBy = ref('risk_score')
  const sortOrder = ref('desc')

  // Filters
  const filters = ref({
    severity: null,
    status: null,
    tool: null,
    cloud_provider: null,
    resource_type: null,
    search: '',
  })

  // Available filter options (populated from summary API)
  const filterOptions = ref({
    severities: ['critical', 'high', 'medium', 'low', 'info'],
    statuses: ['open', 'closed', 'mitigated', 'accepted'],
    tools: [],
    cloudProviders: [],
    resourceTypes: [],
  })

  // Summary data for quick filters
  const summary = ref({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    by_tool: {},
    by_provider: {},
  })

  // Computed
  const hasFilters = computed(() => {
    return Object.values(filters.value).some(v => v !== null && v !== '')
  })

  const totalPages = computed(() => {
    return Math.ceil(total.value / pageSize.value)
  })

  // Actions
  async function fetchFindings() {
    loading.value = true
    error.value = null

    try {
      const params = {
        page: page.value,
        page_size: pageSize.value,
        sort_by: sortBy.value,
        sort_order: sortOrder.value,
        ...filters.value,
      }

      // Remove null/empty filter values
      Object.keys(params).forEach(key => {
        if (params[key] === null || params[key] === '') {
          delete params[key]
        }
      })

      const response = await api.getFindings(params)
      findings.value = response.findings || []
      total.value = response.total || 0

      // Extract unique filter options from data
      updateFilterOptions(findings.value)
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to load findings')
      findings.value = []
      total.value = 0
    } finally {
      loading.value = false
    }
  }

  async function fetchFinding(id) {
    loading.value = true
    error.value = null

    try {
      currentFinding.value = await api.getFinding(id)
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to load finding details')
      currentFinding.value = null
    } finally {
      loading.value = false
    }
  }

  async function updateFinding(id, data) {
    try {
      const updated = await api.updateFinding(id, data)

      // Update in local list if present
      const index = findings.value.findIndex(f => f.id === id)
      if (index !== -1) {
        findings.value[index] = { ...findings.value[index], ...updated }
      }

      // Update current finding if it's the same
      if (currentFinding.value?.id === id) {
        currentFinding.value = { ...currentFinding.value, ...updated }
      }

      toast.success('Finding Updated', 'Status changed successfully')
      return updated
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to update finding')
      throw err
    }
  }

  async function fetchSummary() {
    try {
      const response = await fetch('/api/findings/summary')
      if (!response.ok) throw new Error('Failed to fetch summary')

      const data = await response.json()
      summary.value = data

      // Update filter options from summary
      if (data.by_tool) {
        filterOptions.value.tools = Object.keys(data.by_tool).sort()
      }
      if (data.by_provider) {
        filterOptions.value.cloudProviders = Object.keys(data.by_provider).sort()
      }

      return data
    } catch (err) {
      console.error('Failed to fetch summary:', err)
      return null
    }
  }

  function updateFilterOptions(data) {
    // Only update resource types from current page data
    // Tools and providers come from summary API
    const resourceTypes = new Set()

    data.forEach(finding => {
      if (finding.resource_type) resourceTypes.add(finding.resource_type)
    })

    if (resourceTypes.size > 0) {
      filterOptions.value.resourceTypes = [...resourceTypes].sort()
    }
  }

  function setFilter(key, value) {
    filters.value[key] = value
    page.value = 1 // Reset to first page when filtering
  }

  function clearFilters() {
    filters.value = {
      severity: null,
      status: null,
      tool: null,
      cloud_provider: null,
      resource_type: null,
      search: '',
    }
    page.value = 1
  }

  function setPage(newPage) {
    page.value = newPage
  }

  function setPageSize(newSize) {
    pageSize.value = newSize
    page.value = 1
  }

  function setSort(field, order) {
    // Map frontend field names to backend field names
    const fieldMapping = {
      'severity': 'severity',
      'risk_score': 'risk_score',
      'scan_date': 'scan_date',
      'title': 'title',
      'tool': 'tool',
      'resource_type': 'resource_type',
      'region': 'region',
      'status': 'status',
    }

    const mappedField = fieldMapping[field] || 'risk_score'
    sortBy.value = mappedField
    sortOrder.value = order === 1 ? 'asc' : 'desc'
    page.value = 1 // Reset to first page when sorting
  }

  return {
    // State
    findings,
    currentFinding,
    total,
    page,
    pageSize,
    loading,
    error,
    filters,
    filterOptions,
    summary,
    sortBy,
    sortOrder,

    // Computed
    hasFilters,
    totalPages,

    // Actions
    fetchFindings,
    fetchFinding,
    updateFinding,
    fetchSummary,
    setFilter,
    clearFilters,
    setPage,
    setPageSize,
    setSort,
  }
})
