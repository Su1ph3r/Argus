import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { toast } from '../services/toast'

export const useAnalysisJobsStore = defineStore('analysisJobs', () => {
  // State
  const jobs = ref([])
  const currentJob = ref(null)
  const loading = ref(false)
  const error = ref(null)

  // Polling state
  const pollingIntervals = ref({})

  // Computed
  const pendingJobs = computed(() => {
    return jobs.value.filter(j => j.status === 'pending' || j.status === 'running')
  })

  const completedJobs = computed(() => {
    return jobs.value.filter(j => j.status === 'completed')
  })

  const failedJobs = computed(() => {
    return jobs.value.filter(j => j.status === 'failed')
  })

  // Actions
  async function startAttackPathAnalysis(scanId = null) {
    loading.value = true
    error.value = null

    try {
      const body = scanId ? { scan_id: scanId } : {}

      const response = await fetch('/api/attack-paths/analyze-async', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || 'Failed to start analysis')
      }

      const job = await response.json()
      jobs.value.unshift(job)

      // Start polling for this job
      startPolling(job.job_id)

      toast.info('Analysis Started', 'Attack path analysis is running in the background')
      return job
    } catch (err) {
      error.value = err.message
      toast.apiError(err, 'Failed to start analysis')
      throw err
    } finally {
      loading.value = false
    }
  }

  async function fetchJobStatus(jobId) {
    try {
      const response = await fetch(`/api/attack-paths/analysis-status/${jobId}`)
      if (!response.ok) throw new Error('Failed to fetch job status')

      const job = await response.json()

      // Update in local state
      const index = jobs.value.findIndex(j => j.job_id === jobId)
      if (index !== -1) {
        jobs.value[index] = job
      } else {
        jobs.value.push(job)
      }

      // Update current job if it's the same
      if (currentJob.value?.job_id === jobId) {
        currentJob.value = job
      }

      return job
    } catch (err) {
      console.error('Failed to fetch job status:', err)
      throw err
    }
  }

  function startPolling(jobId, intervalMs = 2000) {
    // Stop any existing polling for this job
    stopPolling(jobId)

    const poll = async () => {
      try {
        const job = await fetchJobStatus(jobId)

        // Stop polling if job is complete
        if (job.status === 'completed' || job.status === 'failed') {
          stopPolling(jobId)

          if (job.status === 'completed') {
            toast.success('Analysis Complete', `Found ${job.result_summary?.total_paths || 0} attack paths`)
          } else {
            toast.error('Analysis Failed', job.error_message || 'Unknown error')
          }
        }
      } catch (err) {
        // Stop polling on error
        stopPolling(jobId)
      }
    }

    // Initial poll
    poll()

    // Set up interval
    pollingIntervals.value[jobId] = setInterval(poll, intervalMs)
  }

  function stopPolling(jobId) {
    if (pollingIntervals.value[jobId]) {
      clearInterval(pollingIntervals.value[jobId])
      delete pollingIntervals.value[jobId]
    }
  }

  function stopAllPolling() {
    Object.keys(pollingIntervals.value).forEach(jobId => {
      stopPolling(jobId)
    })
  }

  function setCurrentJob(job) {
    currentJob.value = job
  }

  function clearCurrentJob() {
    currentJob.value = null
  }

  return {
    // State
    jobs,
    currentJob,
    loading,
    error,

    // Computed
    pendingJobs,
    completedJobs,
    failedJobs,

    // Actions
    startAttackPathAnalysis,
    fetchJobStatus,
    startPolling,
    stopPolling,
    stopAllPolling,
    setCurrentJob,
    clearCurrentJob,
  }
})
