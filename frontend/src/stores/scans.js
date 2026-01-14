import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useCredentialsStore } from './credentials'
import { toast } from '../services/toast'

const API_BASE = '/api'

export const useScansStore = defineStore('scans', () => {
  // Access credentials store for session credential status
  const credentialsStore = useCredentialsStore()
  // State
  const scans = ref([])
  const currentScan = ref(null)
  const profiles = ref([])
  const credentialStatus = ref(null)
  const availableTools = ref({}) // Tools by provider
  const loading = ref(false)
  const error = ref(null)
  const pollingIntervals = ref({})
  const scanPreviousStatus = ref({}) // Track previous status for notifications
  const selectedScans = ref([]) // For bulk operations
  const bulkOperationLoading = ref(false)
  const archives = ref([]) // List of archives
  const pagination = ref({
    page: 1,
    pageSize: 20,
    total: 0,
  })

  // Computed
  const runningScans = computed(() =>
    scans.value.filter(s => s.status === 'running'),
  )

  const recentScans = computed(() =>
    scans.value.slice(0, 5),
  )

  const hasRunningScans = computed(() =>
    runningScans.value.length > 0,
  )

  const awsStatus = computed(() => {
    // Check session credentials first (these are verified and ready)
    if (credentialsStore.sessionCredentials?.aws) {
      return 'ready'
    }
    return credentialStatus.value?.summary?.aws || 'unknown'
  })

  const azureStatus = computed(() => {
    if (credentialsStore.sessionCredentials?.azure) {
      return 'ready'
    }
    return credentialStatus.value?.summary?.azure || 'unknown'
  })

  const gcpStatus = computed(() => {
    if (credentialsStore.sessionCredentials?.gcp) {
      return 'ready'
    }
    return credentialStatus.value?.summary?.gcp || 'unknown'
  })

  const kubernetesStatus = computed(() => {
    if (credentialsStore.sessionCredentials?.kubernetes) {
      return 'ready'
    }
    return credentialStatus.value?.summary?.kubernetes || 'unknown'
  })

  // Scans that can be selected for bulk operations (not running)
  const selectableScans = computed(() =>
    scans.value.filter(s => ['completed', 'failed', 'cancelled'].includes(s.status)),
  )

  // Actions
  async function fetchScans(filters = {}) {
    loading.value = true
    error.value = null

    try {
      const params = new URLSearchParams()
      params.append('page', pagination.value.page)
      params.append('page_size', pagination.value.pageSize)

      if (filters.status) {
        params.append('status', filters.status)
      }
      if (filters.tool) {
        params.append('tool', filters.tool)
      }

      const response = await fetch(`${API_BASE}/scans?${params}`)
      if (!response.ok) throw new Error('Failed to fetch scans')

      const data = await response.json()
      scans.value = data.scans
      pagination.value.total = data.total
      return data.scans
    } catch (e) {
      error.value = e.message
      console.error('Error fetching scans:', e)
      return []
    } finally {
      loading.value = false
    }
  }

  async function fetchScan(scanId) {
    try {
      const response = await fetch(`${API_BASE}/scans/${scanId}`)
      if (!response.ok) throw new Error('Failed to fetch scan')

      const data = await response.json()
      currentScan.value = data
      return data
    } catch (e) {
      console.error('Error fetching scan:', e)
      return null
    }
  }

  async function fetchToolsForProvider(provider) {
    try {
      const response = await fetch(`${API_BASE}/scans/tools/${provider}`)
      if (!response.ok) throw new Error('Failed to fetch tools')

      const data = await response.json()
      availableTools.value[provider] = data.tools
      return data.tools
    } catch (e) {
      console.error('Error fetching tools for provider:', e)
      return []
    }
  }

  async function fetchAllTools() {
    try {
      const response = await fetch(`${API_BASE}/scans/tools`)
      if (!response.ok) throw new Error('Failed to fetch tools')

      const data = await response.json()
      availableTools.value = data.tools_by_provider
      return data.tools_by_provider
    } catch (e) {
      console.error('Error fetching all tools:', e)
      return {}
    }
  }

  async function createScan(config = {}) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile: config.profile || 'quick',
          provider: config.provider || null,
          tools: config.tools && config.tools.length > 0 ? config.tools : null,
          target: config.target || null,
          severity_filter: config.severityFilter || null,
          dry_run: config.dryRun || false,
        }),
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || 'Failed to create scan')
      }

      const data = await response.json()

      // Add to local state
      scans.value.unshift(data)

      // Show notification
      const profileName = profiles.value.find(p => p.id === config.profile)?.name || config.profile
      toast.info('Scan Started', `${profileName} scan has been initiated`, 4000)

      // Start polling for status updates
      if (data.scan_id) {
        scanPreviousStatus.value[data.scan_id] = 'running'
        startPolling(data.scan_id)
      }

      return data
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function cancelScan(scanId) {
    try {
      const response = await fetch(`${API_BASE}/scans/${scanId}`, {
        method: 'DELETE',
      })
      if (!response.ok) throw new Error('Failed to cancel scan')

      stopPolling(scanId)

      // Update local state
      const idx = scans.value.findIndex(s => s.scan_id === scanId)
      if (idx !== -1) {
        scans.value[idx].status = 'cancelled'
      }

      return await response.json()
    } catch (e) {
      error.value = e.message
      throw e
    }
  }

  async function fetchProfiles() {
    try {
      // Static profiles for now - could be fetched from API
      profiles.value = [
        {
          id: 'quick',
          name: 'Quick Scan',
          description: '5-10 minute fast security assessment',
          estimatedTime: '5-10 min',
          tools: ['prowler', 'kubescape'],
        },
        {
          id: 'comprehensive',
          name: 'Full Scan',
          description: 'Complete security audit with all tools',
          estimatedTime: '30-60 min',
          tools: ['prowler', 'scoutsuite', 'kubescape', 'trivy', 'checkov'],
        },
        {
          id: 'compliance-only',
          name: 'Compliance',
          description: 'Compliance-focused security checks',
          estimatedTime: '15-20 min',
          tools: ['prowler', 'kube-bench'],
        },
      ]
      return profiles.value
    } catch (e) {
      console.error('Error fetching profiles:', e)
      return []
    }
  }

  async function fetchCredentialStatus() {
    try {
      const response = await fetch(`${API_BASE}/credentials/status`)
      if (!response.ok) throw new Error('Failed to fetch credential status')

      credentialStatus.value = await response.json()
      return credentialStatus.value
    } catch (e) {
      console.error('Error fetching credential status:', e)
      return null
    }
  }

  // Polling for scan status
  function startPolling(scanId, callback = null, interval = 5000) {
    if (pollingIntervals.value[scanId]) {
      return
    }

    const poll = async () => {
      const scan = await fetchScan(scanId)

      if (scan) {
        // Update in local state
        const idx = scans.value.findIndex(s => s.scan_id === scanId)
        if (idx !== -1) {
          scans.value[idx] = scan
        }

        // Check for status change and notify
        const previousStatus = scanPreviousStatus.value[scanId]
        if (previousStatus && previousStatus !== scan.status) {
          if (scan.status === 'completed') {
            toast.success('Scan Completed', `Found ${scan.total_findings || 0} findings`, 5000)
          } else if (scan.status === 'failed') {
            // Show specific error message if available in metadata
            const errorMsg = scan.scan_metadata?.error || 'Check scan details for error information'
            toast.error('Scan Failed', errorMsg, 5000)
          } else if (scan.status === 'cancelled') {
            toast.warn('Scan Cancelled', 'The scan was cancelled', 4000)
          }
        }
        scanPreviousStatus.value[scanId] = scan.status

        if (callback) {
          callback(scan)
        }

        // Stop polling if scan is complete
        if (['completed', 'failed', 'cancelled'].includes(scan.status)) {
          stopPolling(scanId)
          // Clean up previous status tracking
          delete scanPreviousStatus.value[scanId]
        }
      }
    }

    poll()
    pollingIntervals.value[scanId] = setInterval(poll, interval)
  }

  function stopPolling(scanId) {
    if (pollingIntervals.value[scanId]) {
      clearInterval(pollingIntervals.value[scanId])
      delete pollingIntervals.value[scanId]
    }
  }

  function stopAllPolling() {
    Object.keys(pollingIntervals.value).forEach(id => {
      stopPolling(id)
    })
  }

  // Bulk Operations

  async function bulkDeleteScans(scanIds, deleteFiles = true) {
    bulkOperationLoading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/scans/bulk`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_ids: scanIds,
          delete_files: deleteFiles,
        }),
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || 'Failed to delete scans')
      }

      const result = await response.json()

      // Refresh scans list
      await fetchScans()

      // Clear selection
      selectedScans.value = []

      // Notify user
      if (result.success) {
        toast.success('Scans Deleted', `Deleted ${result.deleted_scans} scans and ${result.deleted_files} files`, 5000)
      } else {
        const msg = result.skipped_scans.length > 0
          ? `Deleted ${result.deleted_scans} scans. Skipped ${result.skipped_scans.length} running scans.`
          : `Deleted ${result.deleted_scans} scans with ${result.errors.length} errors.`
        toast.warn('Partial Success', msg, 5000)
      }

      return result
    } catch (e) {
      error.value = e.message
      toast.error('Delete Failed', e.message, 5000)
      throw e
    } finally {
      bulkOperationLoading.value = false
    }
  }

  async function bulkArchiveScans(scanIds) {
    bulkOperationLoading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/scans/bulk/archive`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_ids: scanIds,
        }),
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || 'Failed to archive scans')
      }

      const result = await response.json()

      // Refresh scans list
      await fetchScans()

      // Refresh archives list
      await fetchArchives()

      // Clear selection
      selectedScans.value = []

      // Notify user
      toast.success('Scans Archived', `Archived ${result.archived_scans} scans to ${result.archive_name}`, 5000)

      return result
    } catch (e) {
      error.value = e.message
      toast.error('Archive Failed', e.message, 5000)
      throw e
    } finally {
      bulkOperationLoading.value = false
    }
  }

  async function fetchArchives() {
    try {
      const response = await fetch(`${API_BASE}/scans/archives`)
      if (!response.ok) throw new Error('Failed to fetch archives')

      const data = await response.json()
      archives.value = data.archives
      return data.archives
    } catch (e) {
      console.error('Error fetching archives:', e)
      toast.apiError(e, 'Failed to load archives')
      return []
    }
  }

  function clearSelection() {
    selectedScans.value = []
  }

  return {
    // State
    scans,
    currentScan,
    profiles,
    credentialStatus,
    availableTools,
    loading,
    error,
    pagination,
    selectedScans,
    bulkOperationLoading,
    archives,

    // Computed
    runningScans,
    recentScans,
    hasRunningScans,
    awsStatus,
    azureStatus,
    gcpStatus,
    kubernetesStatus,
    selectableScans,

    // Actions
    fetchScans,
    fetchScan,
    createScan,
    cancelScan,
    fetchProfiles,
    fetchCredentialStatus,
    fetchToolsForProvider,
    fetchAllTools,
    startPolling,
    stopPolling,
    stopAllPolling,
    bulkDeleteScans,
    bulkArchiveScans,
    fetchArchives,
    clearSelection,
  }
})
