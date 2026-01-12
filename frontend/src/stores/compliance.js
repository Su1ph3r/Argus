import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../services/api'

export const useComplianceStore = defineStore('compliance', () => {
  // State
  const frameworks = ref([])
  const controls = ref([])
  const summary = ref(null)
  const selectedFramework = ref(null)
  const selectedControl = ref(null)
  const controlDetail = ref(null)
  const loading = ref(false)
  const controlLoading = ref(false)
  const error = ref(null)

  // Computed
  const hasData = computed(() => frameworks.value.length > 0)

  const frameworkOptions = computed(() => {
    return frameworks.value.map(f => ({
      label: f.framework,
      value: f.framework,
    }))
  })

  // Actions
  async function fetchFrameworks() {
    loading.value = true
    error.value = null
    try {
      const response = await api.getComplianceFrameworks()
      frameworks.value = response.frameworks || []
    } catch (err) {
      error.value = err.message || 'Failed to load compliance frameworks'
      frameworks.value = []
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary() {
    loading.value = true
    error.value = null
    try {
      const response = await api.getComplianceSummary()
      summary.value = response
      frameworks.value = response.by_framework || []
    } catch (err) {
      error.value = err.message || 'Failed to load compliance summary'
      summary.value = null
    } finally {
      loading.value = false
    }
  }

  async function fetchFrameworkDetails(framework) {
    loading.value = true
    error.value = null
    try {
      const response = await api.getComplianceFrameworkDetails(framework)
      controls.value = response.controls || []
      selectedFramework.value = framework
    } catch (err) {
      error.value = err.message || `Failed to load details for ${framework}`
      controls.value = []
    } finally {
      loading.value = false
    }
  }

  function selectFramework(framework) {
    if (framework) {
      fetchFrameworkDetails(framework)
    } else {
      selectedFramework.value = null
      controls.value = []
    }
  }

  function clearSelection() {
    selectedFramework.value = null
    controls.value = []
    clearControlSelection()
  }

  async function fetchControlDetails(framework, controlId) {
    controlLoading.value = true
    error.value = null
    try {
      const response = await api.getComplianceControlDetails(framework, controlId)
      controlDetail.value = response
      selectedControl.value = controlId
    } catch (err) {
      error.value = err.message || `Failed to load control details for ${controlId}`
      controlDetail.value = null
    } finally {
      controlLoading.value = false
    }
  }

  function selectControl(controlId) {
    if (controlId && selectedFramework.value) {
      fetchControlDetails(selectedFramework.value, controlId)
    } else {
      clearControlSelection()
    }
  }

  function clearControlSelection() {
    selectedControl.value = null
    controlDetail.value = null
  }

  return {
    // State
    frameworks,
    controls,
    summary,
    selectedFramework,
    selectedControl,
    controlDetail,
    loading,
    controlLoading,
    error,
    // Computed
    hasData,
    frameworkOptions,
    // Actions
    fetchFrameworks,
    fetchSummary,
    fetchFrameworkDetails,
    selectFramework,
    clearSelection,
    fetchControlDetails,
    selectControl,
    clearControlSelection,
  }
})
