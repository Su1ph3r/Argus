import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const API_BASE = '/api'

export const useSettingsStore = defineStore('settings', () => {
  // State
  const settings = ref([])
  const settingsByCategory = ref({
    scans: {},
    data: {},
    notifications: {},
    display: {},
  })
  const loading = ref(false)
  const saving = ref(false)
  const error = ref(null)
  const lastSaved = ref(null)

  // Computed - Scan Settings
  const defaultScanProfile = computed(() =>
    settingsByCategory.value.scans?.default_scan_profile || 'quick',
  )

  const defaultRegions = computed(() =>
    settingsByCategory.value.scans?.default_regions || ['us-east-1', 'us-west-2'],
  )

  const defaultSeverityFilter = computed(() =>
    settingsByCategory.value.scans?.default_severity_filter || ['critical', 'high'],
  )

  const maxConcurrentScans = computed(() =>
    settingsByCategory.value.scans?.max_concurrent_scans || 3,
  )

  // Computed - Data Settings
  const autoCleanupDays = computed(() =>
    settingsByCategory.value.data?.auto_cleanup_days || 90,
  )

  const exportFormat = computed(() =>
    settingsByCategory.value.data?.export_format || 'json',
  )

  // Computed - Notification Settings
  const notificationsEnabled = computed(() =>
    settingsByCategory.value.notifications?.notifications_enabled || false,
  )

  const webhookUrl = computed(() =>
    settingsByCategory.value.notifications?.webhook_url || null,
  )

  const emailAlertsEnabled = computed(() =>
    settingsByCategory.value.notifications?.email_alerts_enabled || false,
  )

  // Computed - Display Settings
  const theme = computed(() =>
    settingsByCategory.value.display?.theme || 'dark',
  )

  const findingsPerPage = computed(() =>
    settingsByCategory.value.display?.findings_per_page || 50,
  )

  // Actions
  async function fetchSettings() {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/settings`)
      if (!response.ok) throw new Error('Failed to fetch settings')

      const data = await response.json()
      settings.value = data.settings

      // Group by category
      const grouped = {
        scans: {},
        data: {},
        notifications: {},
        display: {},
      }

      for (const setting of data.settings) {
        if (grouped[setting.category]) {
          grouped[setting.category][setting.setting_key] = setting.setting_value
        }
      }

      settingsByCategory.value = grouped
      return data.settings
    } catch (e) {
      error.value = e.message
      console.error('Error fetching settings:', e)
      return []
    } finally {
      loading.value = false
    }
  }

  async function fetchSettingsGrouped() {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/settings/grouped`)
      if (!response.ok) throw new Error('Failed to fetch settings')

      const data = await response.json()
      settingsByCategory.value = data
      return data
    } catch (e) {
      error.value = e.message
      console.error('Error fetching grouped settings:', e)
      return null
    } finally {
      loading.value = false
    }
  }

  async function getSetting(key) {
    try {
      const response = await fetch(`${API_BASE}/settings/${key}`)
      if (!response.ok) throw new Error(`Failed to fetch setting: ${key}`)

      return await response.json()
    } catch (e) {
      console.error(`Error fetching setting ${key}:`, e)
      return null
    }
  }

  async function updateSetting(key, value) {
    saving.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/settings/${key}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || `Failed to update setting: ${key}`)
      }

      const data = await response.json()

      // Update local state
      const idx = settings.value.findIndex(s => s.setting_key === key)
      if (idx !== -1) {
        settings.value[idx] = data
      }

      // Update grouped state
      if (data.category && settingsByCategory.value[data.category]) {
        settingsByCategory.value[data.category][key] = value
      }

      lastSaved.value = new Date()
      return data
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      saving.value = false
    }
  }

  async function updateMultipleSettings(updates) {
    saving.value = true
    error.value = null

    const results = []
    const errors = []

    try {
      for (const [key, value] of Object.entries(updates)) {
        try {
          const result = await updateSetting(key, value)
          results.push(result)
        } catch (e) {
          errors.push({ key, error: e.message })
        }
      }

      if (errors.length > 0) {
        error.value = `Failed to update: ${errors.map(e => e.key).join(', ')}`
      }

      lastSaved.value = new Date()
      return { results, errors }
    } finally {
      saving.value = false
    }
  }

  async function resetSettings(category = null) {
    loading.value = true
    error.value = null

    try {
      const params = category ? `?category=${category}` : ''
      const response = await fetch(`${API_BASE}/settings/reset${params}`, {
        method: 'POST',
      })

      if (!response.ok) throw new Error('Failed to reset settings')

      const data = await response.json()

      // Refresh settings
      await fetchSettings()

      return data
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function fetchSettingsByCategory(category) {
    try {
      const response = await fetch(`${API_BASE}/settings/category/${category}`)
      if (!response.ok) throw new Error(`Failed to fetch ${category} settings`)

      const data = await response.json()
      return data.settings
    } catch (e) {
      console.error(`Error fetching ${category} settings:`, e)
      return []
    }
  }

  return {
    // State
    settings,
    settingsByCategory,
    loading,
    saving,
    error,
    lastSaved,

    // Computed - Scan Settings
    defaultScanProfile,
    defaultRegions,
    defaultSeverityFilter,
    maxConcurrentScans,

    // Computed - Data Settings
    autoCleanupDays,
    exportFormat,

    // Computed - Notification Settings
    notificationsEnabled,
    webhookUrl,
    emailAlertsEnabled,

    // Computed - Display Settings
    theme,
    findingsPerPage,

    // Actions
    fetchSettings,
    fetchSettingsGrouped,
    getSetting,
    updateSetting,
    updateMultipleSettings,
    resetSettings,
    fetchSettingsByCategory,
  }
})
