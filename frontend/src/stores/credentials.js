import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { toast } from '../services/toast'

const API_BASE = '/api'

// Event for credential status changes
const credentialStatusCallbacks = []

export function onCredentialStatusChange(callback) {
  credentialStatusCallbacks.push(callback)
  return () => {
    const idx = credentialStatusCallbacks.indexOf(callback)
    if (idx > -1) credentialStatusCallbacks.splice(idx, 1)
  }
}

function notifyCredentialStatusChange() {
  credentialStatusCallbacks.forEach(cb => cb())
}

export const useCredentialsStore = defineStore('credentials', () => {
  // State
  const verificationResult = ref(null)
  const credentialStatus = ref(null)
  const providers = ref([])
  const loading = ref(false)
  const error = ref(null)

  // Session credentials (stored in memory only, not persisted)
  const sessionCredentials = ref({
    aws: null,
    azure: null,
    gcp: null,
    kubernetes: null,
  })

  // AWS Profiles from mounted credentials file
  const awsProfiles = ref([])
  const selectedAwsProfile = ref(null)
  const awsProfilesLoading = ref(false)

  // Azure Profiles from stored credentials
  const azureProfiles = ref([])
  const selectedAzureProfile = ref(null)
  const azureProfilesLoading = ref(false)

  // Computed
  const isVerified = computed(() => verificationResult.value?.success === true)

  const hasSessionCredentials = computed(() => {
    return Object.values(sessionCredentials.value).some(c => c !== null)
  })

  const activeSessionProviders = computed(() => {
    return Object.entries(sessionCredentials.value)
      .filter(([, creds]) => creds !== null)
      .map(([provider]) => provider)
  })

  const configuredProviders = computed(() => {
    if (!credentialStatus.value?.providers) return []
    return Object.entries(credentialStatus.value.providers)
      .filter(([, info]) => info.configured)
      .map(([name]) => name)
  })

  const passedTools = computed(() => {
    if (!verificationResult.value?.results) return []
    const tools = []
    for (const provider of verificationResult.value.results) {
      for (const tool of provider.tools || []) {
        if (tool.passed) {
          tools.push({
            ...tool,
            provider: provider.provider,
          })
        }
      }
    }
    return tools
  })

  const failedTools = computed(() => {
    if (!verificationResult.value?.results) return []
    const tools = []
    for (const provider of verificationResult.value.results) {
      for (const tool of provider.tools || []) {
        if (!tool.passed) {
          tools.push({
            ...tool,
            provider: provider.provider,
          })
        }
      }
    }
    return tools
  })

  // Actions
  async function fetchStatus() {
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

  async function fetchProviders() {
    try {
      const response = await fetch(`${API_BASE}/credentials/providers`)
      if (!response.ok) throw new Error('Failed to fetch providers')

      const data = await response.json()
      providers.value = data.providers
      return providers.value
    } catch (e) {
      console.error('Error fetching providers:', e)
      return []
    }
  }

  async function verifyCredentials(request = {}) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/credentials/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      })

      if (!response.ok) throw new Error('Failed to verify credentials')

      verificationResult.value = await response.json()
      toast.success('Verification Complete', 'Credentials verified successfully')
      return verificationResult.value
    } catch (e) {
      error.value = e.message
      toast.apiError(e, 'Credential verification failed')
      throw e
    } finally {
      loading.value = false
    }
  }

  async function verifyProvider(provider, includeRemediation = false) {
    return await verifyCredentials({
      provider,
      include_remediation: includeRemediation,
    })
  }

  async function verifyEnhanced(request = {}) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/credentials/verify-enhanced`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      })

      if (!response.ok) throw new Error('Failed to verify credentials')

      verificationResult.value = await response.json()
      toast.success('Verification Complete', 'Enhanced verification completed')
      return verificationResult.value
    } catch (e) {
      error.value = e.message
      toast.apiError(e, 'Enhanced verification failed')
      throw e
    } finally {
      loading.value = false
    }
  }

  async function fetchToolRequirements() {
    try {
      const response = await fetch(`${API_BASE}/credentials/requirements`)
      if (!response.ok) throw new Error('Failed to fetch requirements')

      return await response.json()
    } catch (e) {
      console.error('Error fetching requirements:', e)
      return null
    }
  }

  function clearResults() {
    verificationResult.value = null
    error.value = null
  }

  // Session credential management
  function setSessionCredentials(provider, credentials) {
    if (sessionCredentials.value.hasOwnProperty(provider)) {
      sessionCredentials.value[provider] = credentials
      // Notify listeners that credential status has changed
      notifyCredentialStatusChange()
    }
  }

  function getSessionCredentials(provider) {
    return sessionCredentials.value[provider]
  }

  function clearSessionCredentials(provider = null) {
    if (provider) {
      if (sessionCredentials.value.hasOwnProperty(provider)) {
        sessionCredentials.value[provider] = null
      }
    } else {
      sessionCredentials.value = {
        aws: null,
        azure: null,
        gcp: null,
        kubernetes: null,
      }
    }
  }

  // AWS Profile management
  async function fetchAwsProfiles() {
    awsProfilesLoading.value = true
    try {
      const response = await fetch(`${API_BASE}/aws-profiles`)
      if (!response.ok) throw new Error('Failed to fetch AWS profiles')

      const data = await response.json()
      awsProfiles.value = data.profiles || []
      return awsProfiles.value
    } catch (e) {
      console.error('Error fetching AWS profiles:', e)
      awsProfiles.value = []
      return []
    } finally {
      awsProfilesLoading.value = false
    }
  }

  async function verifyAwsProfile(profileName) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/aws-profiles/${profileName}/verify`, {
        method: 'POST',
      })

      if (!response.ok) throw new Error('Failed to verify profile')

      const result = await response.json()
      return result
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function selectAwsProfile(profileName) {
    // Verify the profile first
    const result = await verifyAwsProfile(profileName)

    if (result.valid) {
      selectedAwsProfile.value = profileName

      // Fetch credentials and store in session
      try {
        const response = await fetch(`${API_BASE}/aws-profiles/${profileName}/credentials`)
        if (response.ok) {
          const creds = await response.json()
          sessionCredentials.value.aws = {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            region: creds.region || 'us-east-1',
            profile: profileName,
          }
          // Persist the selected profile name in localStorage
          localStorage.setItem('selectedAwsProfile', profileName)
          // Notify listeners that credential status has changed
          notifyCredentialStatusChange()
          toast.success('Profile Selected', `Using AWS profile: ${profileName}`)
        }
      } catch (e) {
        console.error('Error fetching profile credentials:', e)
        toast.error('Profile Error', 'Failed to fetch profile credentials')
      }

      return { success: true, ...result }
    } else {
      toast.error('Profile Invalid', result.error || 'Profile verification failed')
      return { success: false, ...result }
    }
  }

  function clearAwsProfile() {
    selectedAwsProfile.value = null
    sessionCredentials.value.aws = null
    localStorage.removeItem('selectedAwsProfile')
    // Notify listeners that credential status has changed
    notifyCredentialStatusChange()
  }

  // Restore persisted profile on init
  async function restoreAwsProfile() {
    const savedProfile = localStorage.getItem('selectedAwsProfile')
    if (savedProfile) {
      // Fetch profiles first if not loaded
      if (awsProfiles.value.length === 0) {
        await fetchAwsProfiles()
      }
      // Check if the saved profile still exists
      const profileExists = awsProfiles.value.some(p => p.name === savedProfile)
      if (profileExists) {
        // Re-select the profile (will verify and fetch credentials)
        await selectAwsProfile(savedProfile)
      } else {
        // Profile no longer exists, clear the saved value
        localStorage.removeItem('selectedAwsProfile')
      }
    }
  }

  // Azure Profile management
  async function fetchAzureProfiles() {
    azureProfilesLoading.value = true
    try {
      const response = await fetch(`${API_BASE}/azure-profiles`)
      if (!response.ok) throw new Error('Failed to fetch Azure profiles')

      const data = await response.json()
      azureProfiles.value = data.profiles || []
      return azureProfiles.value
    } catch (e) {
      console.error('Error fetching Azure profiles:', e)
      azureProfiles.value = []
      return []
    } finally {
      azureProfilesLoading.value = false
    }
  }

  async function verifyAzureProfile(profileName) {
    loading.value = true
    error.value = null

    try {
      const response = await fetch(`${API_BASE}/azure-profiles/${profileName}/verify`, {
        method: 'POST',
      })

      if (!response.ok) throw new Error('Failed to verify Azure profile')

      const result = await response.json()
      return result
    } catch (e) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function selectAzureProfile(profileName) {
    // Verify the profile first
    const result = await verifyAzureProfile(profileName)

    if (result.valid) {
      selectedAzureProfile.value = profileName

      // Fetch credentials and store in session
      try {
        const response = await fetch(`${API_BASE}/azure-profiles/${profileName}/credentials`)
        if (response.ok) {
          const creds = await response.json()
          sessionCredentials.value.azure = {
            tenant_id: creds.tenant_id,
            client_id: creds.client_id,
            client_secret: creds.client_secret,
            subscription_id: creds.subscription_id,
            profile: profileName,
          }
          // Persist the selected profile name in localStorage
          localStorage.setItem('selectedAzureProfile', profileName)
          // Notify listeners that credential status has changed
          notifyCredentialStatusChange()
          toast.success('Profile Selected', `Using Azure profile: ${profileName}`)
        }
      } catch (e) {
        console.error('Error fetching Azure profile credentials:', e)
        toast.error('Profile Error', 'Failed to fetch Azure profile credentials')
      }

      return { success: true, ...result }
    } else {
      toast.error('Profile Invalid', result.error || 'Azure profile verification failed')
      return { success: false, ...result }
    }
  }

  function clearAzureProfile() {
    selectedAzureProfile.value = null
    sessionCredentials.value.azure = null
    localStorage.removeItem('selectedAzureProfile')
    // Notify listeners that credential status has changed
    notifyCredentialStatusChange()
  }

  // Restore persisted Azure profile on init
  async function restoreAzureProfile() {
    const savedProfile = localStorage.getItem('selectedAzureProfile')
    if (savedProfile) {
      // Fetch profiles first if not loaded
      if (azureProfiles.value.length === 0) {
        await fetchAzureProfiles()
      }
      // Check if the saved profile still exists
      const profileExists = azureProfiles.value.some(p => p.name === savedProfile)
      if (profileExists) {
        // Re-select the profile (will verify and fetch credentials)
        await selectAzureProfile(savedProfile)
      } else {
        // Profile no longer exists, clear the saved value
        localStorage.removeItem('selectedAzureProfile')
      }
    }
  }

  return {
    verificationResult,
    credentialStatus,
    providers,
    loading,
    error,
    sessionCredentials,
    awsProfiles,
    selectedAwsProfile,
    awsProfilesLoading,
    azureProfiles,
    selectedAzureProfile,
    azureProfilesLoading,
    isVerified,
    hasSessionCredentials,
    activeSessionProviders,
    configuredProviders,
    passedTools,
    failedTools,
    fetchStatus,
    fetchProviders,
    verifyCredentials,
    verifyProvider,
    verifyEnhanced,
    fetchToolRequirements,
    clearResults,
    setSessionCredentials,
    getSessionCredentials,
    clearSessionCredentials,
    fetchAwsProfiles,
    verifyAwsProfile,
    selectAwsProfile,
    clearAwsProfile,
    restoreAwsProfile,
    fetchAzureProfiles,
    verifyAzureProfile,
    selectAzureProfile,
    clearAzureProfile,
    restoreAzureProfile,
  }
})
