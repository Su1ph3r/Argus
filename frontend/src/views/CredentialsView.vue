<template>
  <div class="credentials-view">
    <div class="page-header">
      <h1>Credential Verification</h1>
      <p class="subtitle">
        Verify cloud provider credentials and check permissions
      </p>
    </div>

    <div class="main-content">
      <!-- Provider Selection Tabs -->
      <div class="provider-tabs">
        <button
          v-for="provider in providers"
          :key="provider.id"
          class="provider-tab"
          :class="{ active: selectedProvider === provider.id }"
          @click="selectProvider(provider.id)"
        >
          <i :class="getProviderIcon(provider.id)" />
          <span>{{ provider.name }}</span>
        </button>
      </div>

      <!-- AWS Profiles from Credentials File -->
      <div
        v-if="selectedProvider === 'aws' && awsProfiles.length > 0"
        class="profiles-section"
      >
        <h3>
          <i class="pi pi-folder" />
          AWS Profiles (from credentials file)
        </h3>
        <p class="profiles-description">
          Select a profile from your mounted AWS credentials file. This is the recommended approach.
        </p>
        <div class="profiles-grid">
          <div
            v-for="profile in awsProfiles"
            :key="profile.name"
            class="profile-card"
            :class="{ selected: selectedAwsProfile === profile.name, verified: profileVerified === profile.name }"
            @click="selectProfile(profile.name)"
          >
            <div class="profile-header">
              <i class="pi pi-user" />
              <span class="profile-name">{{ profile.name }}</span>
              <i
                v-if="selectedAwsProfile === profile.name"
                class="pi pi-check-circle profile-check"
              />
              <button
                class="btn-delete-profile"
                title="Delete profile"
                @click.stop="deleteProfile(profile.name)"
              >
                <i class="pi pi-trash" />
              </button>
            </div>
            <div class="profile-details">
              <span
                v-if="profile.region"
                class="profile-region"
              >
                <i class="pi pi-globe" /> {{ profile.region }}
              </span>
              <span
                v-if="profile.has_session_token"
                class="profile-badge temp"
              >Temporary</span>
            </div>
          </div>
        </div>
        <div
          v-if="selectedAwsProfile"
          class="profile-selected-info"
        >
          <i class="pi pi-check-circle" />
          <span>Profile <strong>{{ selectedAwsProfile }}</strong> is ready for scans</span>
          <button
            class="btn-clear-profile"
            @click="clearProfile"
          >
            <i class="pi pi-times" /> Clear
          </button>
        </div>
      </div>

      <!-- Manual Credential Form -->
      <div
        class="form-section"
        :class="{ collapsed: selectedProvider === 'aws' && awsProfiles.length > 0 && !showManualForm }"
      >
        <div
          v-if="selectedProvider === 'aws' && awsProfiles.length > 0"
          class="manual-toggle"
          @click="showManualForm = !showManualForm"
        >
          <i :class="showManualForm ? 'pi pi-chevron-down' : 'pi pi-chevron-right'" />
          <span>Or enter credentials manually</span>
        </div>
        <h3 v-else>
          Enter {{ getProviderName(selectedProvider) }} Credentials
        </h3>

        <!-- AWS Form -->
        <div
          v-if="selectedProvider === 'aws'"
          class="credential-form"
        >
          <div class="form-group">
            <label for="aws-access-key">Access Key ID <span class="required">*</span></label>
            <input
              id="aws-access-key"
              v-model="awsForm.access_key_id"
              type="text"
              placeholder="AKIAIOSFODNN7EXAMPLE"
              class="form-input"
            >
          </div>
          <div class="form-group">
            <label for="aws-secret-key">Secret Access Key <span class="required">*</span></label>
            <input
              id="aws-secret-key"
              v-model="awsForm.secret_access_key"
              type="password"
              placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              class="form-input"
            >
          </div>
          <div class="form-group">
            <label for="aws-session-token">Session Token (optional)</label>
            <input
              id="aws-session-token"
              v-model="awsForm.session_token"
              type="password"
              placeholder="For temporary credentials only"
              class="form-input"
            >
          </div>
          <div class="form-group">
            <label for="aws-region">Region</label>
            <input
              id="aws-region"
              v-model="awsForm.region"
              type="text"
              placeholder="us-east-1"
              class="form-input"
            >
          </div>
        </div>

        <!-- Azure Form -->
        <div
          v-if="selectedProvider === 'azure'"
          class="credential-form"
        >
          <div class="form-group">
            <label for="azure-tenant">Tenant ID <span class="required">*</span></label>
            <input
              id="azure-tenant"
              v-model="azureForm.tenant_id"
              type="text"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              class="form-input"
            >
          </div>
          <div class="form-group">
            <label for="azure-client">Client/App ID <span class="required">*</span></label>
            <input
              id="azure-client"
              v-model="azureForm.client_id"
              type="text"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              class="form-input"
            >
          </div>
          <div class="form-group">
            <label for="azure-secret">Client Secret <span class="required">*</span></label>
            <input
              id="azure-secret"
              v-model="azureForm.client_secret"
              type="password"
              placeholder="Your client secret"
              class="form-input"
            >
          </div>
          <div class="form-group">
            <label for="azure-subscription">Subscription ID (optional)</label>
            <input
              id="azure-subscription"
              v-model="azureForm.subscription_id"
              type="text"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              class="form-input"
            >
          </div>
        </div>

        <!-- GCP Form -->
        <div
          v-if="selectedProvider === 'gcp'"
          class="credential-form"
        >
          <div class="form-group">
            <label for="gcp-project">Project ID <span class="required">*</span></label>
            <input
              id="gcp-project"
              v-model="gcpForm.project_id"
              type="text"
              placeholder="my-project-123456"
              class="form-input"
            >
          </div>
          <div class="form-group">
            <label for="gcp-json">Service Account JSON <span class="required">*</span></label>
            <textarea
              id="gcp-json"
              v-model="gcpForm.credentials_json"
              placeholder="Paste your service account JSON key here...
{
  &quot;type&quot;: &quot;service_account&quot;,
  &quot;project_id&quot;: &quot;...&quot;,
  &quot;private_key_id&quot;: &quot;...&quot;,
  ...
}"
              class="form-textarea"
              rows="10"
            />
          </div>
        </div>

        <!-- Kubernetes Form -->
        <div
          v-if="selectedProvider === 'kubernetes'"
          class="credential-form"
        >
          <div class="form-group">
            <label for="k8s-kubeconfig">Kubeconfig YAML <span class="required">*</span></label>
            <textarea
              id="k8s-kubeconfig"
              v-model="kubernetesForm.kubeconfig"
              placeholder="Paste your kubeconfig YAML content here...
apiVersion: v1
kind: Config
clusters:
- cluster:
    ..."
              class="form-textarea"
              rows="12"
            />
          </div>
          <div class="form-group">
            <label for="k8s-context">Context Name (optional)</label>
            <input
              id="k8s-context"
              v-model="kubernetesForm.context"
              type="text"
              placeholder="Leave empty to use default context"
              class="form-input"
            >
          </div>
        </div>

        <div class="form-actions">
          <button
            class="btn-verify"
            :disabled="loading || !isFormValid"
            @click="verifyCredentials"
          >
            <i
              v-if="loading"
              class="pi pi-spin pi-spinner"
            />
            <i
              v-else
              class="pi pi-shield"
            />
            {{ loading ? 'Verifying...' : 'Verify Credentials' }}
          </button>
          <button
            class="btn-clear"
            @click="clearForm"
          >
            <i class="pi pi-times" />
            Clear
          </button>
        </div>
      </div>

      <!-- Results Section -->
      <div
        v-if="result"
        class="results-section"
      >
        <div
          class="results-header"
          :class="{ success: result.success, error: !result.success }"
        >
          <i :class="result.success ? 'pi pi-check-circle' : 'pi pi-times-circle'" />
          <span>{{ result.success ? 'Credentials Verified' : 'Verification Failed' }}</span>
        </div>

        <div class="results-code">
          <div class="code-header">
            <span>Verification Output</span>
            <button
              class="btn-copy"
              @click="copyOutput"
            >
              <i class="pi pi-copy" />
              Copy
            </button>
          </div>
          <pre class="code-block">{{ result.raw_output }}</pre>
        </div>

        <!-- Structured Results -->
        <div
          v-if="result.identity"
          class="results-details"
        >
          <div class="detail-item">
            <span class="detail-label">Identity:</span>
            <span class="detail-value">{{ result.identity }}</span>
          </div>
          <div
            v-if="result.account_info"
            class="detail-item"
          >
            <span class="detail-label">Account:</span>
            <span class="detail-value">{{ result.account_info }}</span>
          </div>
          <div
            v-if="result.permissions_available.length > 0"
            class="detail-item"
          >
            <span class="detail-label">Permissions OK:</span>
            <span class="detail-value success-text">{{ result.permissions_available.length }}</span>
          </div>
          <div
            v-if="result.permissions_missing.length > 0"
            class="detail-item"
          >
            <span class="detail-label">Permissions Denied:</span>
            <span class="detail-value error-text">{{ result.permissions_missing.length }}</span>
          </div>
        </div>

        <!-- Use for Scans Section -->
        <div
          v-if="result.success"
          class="use-credentials-section"
        >
          <div class="use-credentials-content">
            <div class="use-credentials-info">
              <i class="pi pi-check-circle" />
              <div>
                <strong>Credentials Verified</strong>
                <p>Save as a profile and use for scans</p>
              </div>
            </div>
            <div class="save-profile-form">
              <input
                v-model="profileNameToSave"
                type="text"
                placeholder="Profile name (e.g., default, production)"
                class="profile-name-input"
                :disabled="savingProfile"
              >
              <button
                class="btn-use-credentials"
                :disabled="savingProfile || !profileNameToSave.trim()"
                @click="useForScans"
              >
                <i :class="savingProfile ? 'pi pi-spin pi-spinner' : 'pi pi-save'" />
                {{ savingProfile ? 'Saving...' : 'Save as Profile' }}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Error Display -->
      <div
        v-if="error"
        class="error-section"
      >
        <i class="pi pi-exclamation-triangle" />
        <span>{{ error }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useCredentialsStore } from '../stores/credentials'
import { useToast } from 'primevue/usetoast'

const API_BASE = '/api'
const credentialsStore = useCredentialsStore()
const toast = useToast()

const selectedProvider = ref('aws')
const loading = ref(false)
const error = ref(null)
const result = ref(null)
const showManualForm = ref(false)
const profileVerified = ref(null)
const profileNameToSave = ref('')
const savingProfile = ref(false)

// Generate a unique profile name based on identity or fallback to numbered names
function generateUniqueProfileName(identity = null) {
  const existingNames = awsProfiles.value.map(p => p.name)

  // Try to extract a meaningful name from identity (e.g., "arn:aws:iam::123456:user/john" -> "john")
  if (identity) {
    let baseName = identity
    // Extract username from ARN if present
    if (identity.includes('/')) {
      baseName = identity.split('/').pop()
    } else if (identity.includes(':user/')) {
      baseName = identity.split(':user/').pop()
    } else if (identity.includes(':role/')) {
      baseName = identity.split(':role/').pop()
    }

    // Clean up the name (remove special chars, make lowercase)
    baseName = baseName.replace(/[^a-zA-Z0-9-_]/g, '-').toLowerCase()

    // If this name doesn't exist, use it
    if (!existingNames.includes(baseName)) {
      return baseName
    }

    // Otherwise, add a number suffix
    let counter = 2
    while (existingNames.includes(`${baseName}-${counter}`)) {
      counter++
    }
    return `${baseName}-${counter}`
  }

  // Fallback: If no identity, use generic naming
  if (existingNames.length === 0) {
    return 'default'
  }

  if (!existingNames.includes('default')) {
    return 'default'
  }

  let counter = 2
  while (existingNames.includes(`profile-${counter}`)) {
    counter++
  }
  return `profile-${counter}`
}

// AWS Profiles from store
const awsProfiles = computed(() => credentialsStore.awsProfiles)
const selectedAwsProfile = computed(() => credentialsStore.selectedAwsProfile)

// Fetch AWS profiles on mount
onMounted(async () => {
  await credentialsStore.fetchAwsProfiles()
})

// Profile selection
async function selectProfile(profileName) {
  loading.value = true
  error.value = null
  result.value = null

  try {
    const selectResult = await credentialsStore.selectAwsProfile(profileName)

    if (selectResult.success) {
      profileVerified.value = profileName
      toast.add({
        severity: 'success',
        summary: 'Profile Ready',
        detail: `AWS profile "${profileName}" verified and ready for scans`,
        life: 4000,
      })
    } else {
      toast.add({
        severity: 'error',
        summary: 'Verification Failed',
        detail: selectResult.message || 'Could not verify profile credentials',
        life: 5000,
      })
    }
  } catch (e) {
    error.value = e.message
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: e.message,
      life: 5000,
    })
  } finally {
    loading.value = false
  }
}

function clearProfile() {
  credentialsStore.clearAwsProfile()
  profileVerified.value = null
  toast.add({
    severity: 'info',
    summary: 'Profile Cleared',
    detail: 'AWS profile selection cleared',
    life: 3000,
  })
}

async function deleteProfile(profileName) {
  try {
    const response = await fetch(`${API_BASE}/aws-profiles/${profileName}`, {
      method: 'DELETE',
    })
    if (!response.ok) {
      const errData = await response.json()
      throw new Error(errData.detail || 'Failed to delete profile')
    }

    // Refresh the profiles list
    await credentialsStore.fetchAwsProfiles()

    // Clear selection if we deleted the selected profile
    if (selectedAwsProfile.value === profileName) {
      credentialsStore.clearAwsProfile()
      profileVerified.value = null
    }

    toast.add({
      severity: 'success',
      summary: 'Profile Deleted',
      detail: `AWS profile "${profileName}" deleted`,
      life: 3000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Delete Failed',
      detail: e.message,
      life: 5000,
    })
  }
}

const providers = [
  { id: 'aws', name: 'AWS' },
  { id: 'azure', name: 'Azure' },
  { id: 'gcp', name: 'GCP' },
  { id: 'kubernetes', name: 'Kubernetes' },
]

const awsForm = ref({
  access_key_id: '',
  secret_access_key: '',
  session_token: '',
  region: 'us-east-1',
})

const azureForm = ref({
  tenant_id: '',
  client_id: '',
  client_secret: '',
  subscription_id: '',
})

const gcpForm = ref({
  project_id: '',
  credentials_json: '',
})

const kubernetesForm = ref({
  kubeconfig: '',
  context: '',
})

const providerIcons = {
  aws: 'pi pi-amazon',
  azure: 'pi pi-microsoft',
  gcp: 'pi pi-google',
  kubernetes: 'pi pi-server',
}

function getProviderIcon(id) {
  return providerIcons[id] || 'pi pi-cloud'
}

function getProviderName(id) {
  const names = {
    aws: 'AWS',
    azure: 'Azure',
    gcp: 'GCP',
    kubernetes: 'Kubernetes',
  }
  return names[id] || id
}

const isFormValid = computed(() => {
  if (selectedProvider.value === 'aws') {
    return awsForm.value.access_key_id && awsForm.value.secret_access_key
  } else if (selectedProvider.value === 'azure') {
    return azureForm.value.tenant_id && azureForm.value.client_id && azureForm.value.client_secret
  } else if (selectedProvider.value === 'gcp') {
    return gcpForm.value.project_id && gcpForm.value.credentials_json
  } else if (selectedProvider.value === 'kubernetes') {
    return kubernetesForm.value.kubeconfig
  }
  return false
})

function selectProvider(id) {
  selectedProvider.value = id
  result.value = null
  error.value = null
}

function clearForm() {
  if (selectedProvider.value === 'aws') {
    awsForm.value = { access_key_id: '', secret_access_key: '', session_token: '', region: 'us-east-1' }
  } else if (selectedProvider.value === 'azure') {
    azureForm.value = { tenant_id: '', client_id: '', client_secret: '', subscription_id: '' }
  } else if (selectedProvider.value === 'gcp') {
    gcpForm.value = { project_id: '', credentials_json: '' }
  } else if (selectedProvider.value === 'kubernetes') {
    kubernetesForm.value = { kubeconfig: '', context: '' }
  }
  result.value = null
  error.value = null
  profileNameToSave.value = ''
}

async function verifyCredentials() {
  loading.value = true
  error.value = null
  result.value = null

  try {
    const payload = {
      provider: selectedProvider.value,
    }

    if (selectedProvider.value === 'aws') {
      payload.aws = {
        access_key_id: awsForm.value.access_key_id,
        secret_access_key: awsForm.value.secret_access_key,
        session_token: awsForm.value.session_token || null,
        region: awsForm.value.region || 'us-east-1',
      }
    } else if (selectedProvider.value === 'azure') {
      payload.azure = {
        tenant_id: azureForm.value.tenant_id,
        client_id: azureForm.value.client_id,
        client_secret: azureForm.value.client_secret,
        subscription_id: azureForm.value.subscription_id || null,
      }
    } else if (selectedProvider.value === 'gcp') {
      payload.gcp = {
        project_id: gcpForm.value.project_id,
        credentials_json: gcpForm.value.credentials_json,
      }
    } else if (selectedProvider.value === 'kubernetes') {
      payload.kubernetes = {
        kubeconfig: kubernetesForm.value.kubeconfig,
        context: kubernetesForm.value.context || null,
      }
    }

    const response = await fetch(`${API_BASE}/credentials/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })

    if (!response.ok) {
      const errData = await response.json()
      throw new Error(errData.detail || 'Verification failed')
    }

    result.value = await response.json()

    // Always generate a unique profile name when verification succeeds
    // Use the identity (username/role) from the verification result
    if (result.value.success) {
      // Refresh profiles list to get latest data before generating name
      await credentialsStore.fetchAwsProfiles()
      profileNameToSave.value = generateUniqueProfileName(result.value.identity)
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function copyOutput() {
  if (result.value?.raw_output) {
    navigator.clipboard.writeText(result.value.raw_output)
  }
}

// Check if current provider credentials are stored in session
const isCredentialStored = computed(() => {
  return credentialsStore.getSessionCredentials(selectedProvider.value) !== null
})

// Store verified credentials for use in scans and save as profile
async function useForScans() {
  if (selectedProvider.value === 'aws') {
    // Save to credentials file as a profile
    savingProfile.value = true
    try {
      const response = await fetch(`${API_BASE}/aws-profiles/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile_name: profileNameToSave.value.trim(),
          access_key_id: awsForm.value.access_key_id,
          secret_access_key: awsForm.value.secret_access_key,
          session_token: awsForm.value.session_token || null,
          region: awsForm.value.region || 'us-east-1',
        }),
      })

      if (!response.ok) {
        const errData = await response.json()
        throw new Error(errData.detail || 'Failed to save profile')
      }

      const data = await response.json()

      // Also store in session
      credentialsStore.setSessionCredentials('aws', { ...awsForm.value })

      // Refresh the profiles list
      await credentialsStore.fetchAwsProfiles()

      // Select the newly created profile
      await credentialsStore.selectAwsProfile(profileNameToSave.value.trim())

      toast.add({
        severity: 'success',
        summary: 'Profile Saved',
        detail: `AWS profile "${profileNameToSave.value}" saved and ready for scans (Account: ${data.account})`,
        life: 5000,
      })

      // Reset form to allow adding more profiles
      awsForm.value = { access_key_id: '', secret_access_key: '', session_token: '', region: 'us-east-1' }
      result.value = null
      profileNameToSave.value = ''  // Will be set when next verification succeeds
      showManualForm.value = false
    } catch (e) {
      toast.add({
        severity: 'error',
        summary: 'Save Failed',
        detail: e.message,
        life: 5000,
      })
    } finally {
      savingProfile.value = false
    }
  } else {
    // For other providers, just store in session for now
    let credentials = null

    if (selectedProvider.value === 'azure') {
      credentials = { ...azureForm.value }
    } else if (selectedProvider.value === 'gcp') {
      credentials = { ...gcpForm.value }
    } else if (selectedProvider.value === 'kubernetes') {
      credentials = { ...kubernetesForm.value }
    }

    if (credentials) {
      credentialsStore.setSessionCredentials(selectedProvider.value, credentials)
      toast.add({
        severity: 'success',
        summary: 'Credentials Ready',
        detail: `${getProviderName(selectedProvider.value)} credentials stored for scan use`,
        life: 4000,
      })
    }
  }
}
</script>

<style scoped>
.credentials-view {
  padding: 1.5rem;
  max-width: 900px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 2rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.75rem;
}

.subtitle {
  color: var(--text-color-secondary);
  margin-top: 0.25rem;
}

.main-content {
  background: var(--surface-card);
  border-radius: 8px;
  overflow: hidden;
}

/* Provider Tabs */
.provider-tabs {
  display: flex;
  border-bottom: 1px solid var(--surface-border);
}

.provider-tab {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 1rem;
  border: none;
  background: transparent;
  color: var(--text-color-secondary);
  cursor: pointer;
  font-size: 0.95rem;
  font-weight: 500;
  transition: all 0.15s;
}

.provider-tab:hover {
  background: var(--surface-hover);
  color: var(--text-color);
}

.provider-tab.active {
  background: var(--primary-color);
  color: white;
}

.provider-tab i {
  font-size: 1.1rem;
}

/* Form Section */
.form-section {
  padding: 1.5rem;
}

.form-section h3 {
  margin: 0 0 1.5rem 0;
  font-size: 1.1rem;
  color: var(--text-color);
}

.credential-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--text-color);
}

.required {
  color: var(--red-500);
}

.form-input {
  padding: 0.75rem;
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  font-size: 0.95rem;
  font-family: monospace;
  background: var(--surface-ground);
  color: var(--text-color);
  transition: border-color 0.15s;
}

.form-input:focus {
  outline: none;
  border-color: var(--primary-color);
}

.form-textarea {
  padding: 0.75rem;
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  font-size: 0.9rem;
  font-family: monospace;
  background: var(--surface-ground);
  color: var(--text-color);
  resize: vertical;
  min-height: 150px;
}

.form-textarea:focus {
  outline: none;
  border-color: var(--primary-color);
}

.form-actions {
  display: flex;
  gap: 1rem;
  margin-top: 1.5rem;
}

.btn-verify {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  border: none;
  border-radius: 6px;
  background: var(--primary-color);
  color: white;
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.15s;
}

.btn-verify:hover:not(:disabled) {
  background: var(--primary-600);
}

.btn-verify:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-clear {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  background: transparent;
  color: var(--text-color-secondary);
  font-size: 0.95rem;
  cursor: pointer;
  transition: all 0.15s;
}

.btn-clear:hover {
  border-color: var(--text-color-secondary);
  color: var(--text-color);
}

/* Results Section */
.results-section {
  border-top: 1px solid var(--surface-border);
}

.results-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem 1.5rem;
  font-weight: 600;
}

.results-header.success {
  background: var(--green-50);
  color: var(--green-700);
}

.results-header.error {
  background: var(--red-50);
  color: var(--red-700);
}

.results-header i {
  font-size: 1.25rem;
}

.results-code {
  padding: 0 1.5rem 1.5rem;
}

.code-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.code-header span {
  font-size: 0.9rem;
  color: var(--text-color-secondary);
}

.btn-copy {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border: 1px solid var(--surface-border);
  border-radius: 4px;
  background: transparent;
  color: var(--text-color-secondary);
  font-size: 0.8rem;
  cursor: pointer;
}

.btn-copy:hover {
  background: var(--surface-hover);
}

.code-block {
  margin: 0;
  padding: 1rem;
  background: var(--surface-ground);
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.85rem;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
  color: var(--text-color);
}

.results-details {
  padding: 0 1.5rem 1.5rem;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
}

.detail-item {
  display: flex;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.detail-label {
  color: var(--text-color-secondary);
  font-size: 0.9rem;
}

.detail-value {
  font-weight: 500;
  font-family: monospace;
  font-size: 0.9rem;
}

.success-text {
  color: var(--green-600);
}

.error-text {
  color: var(--red-600);
}

/* Error Section */
.error-section {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem 1.5rem;
  background: var(--red-50);
  color: var(--red-700);
  border-top: 1px solid var(--red-200);
}

.error-section i {
  font-size: 1.1rem;
}

/* Use for Scans Section */
.use-credentials-section {
  padding: 1rem 1.5rem;
  border-top: 1px solid var(--surface-border);
  background: var(--surface-ground);
}

.use-credentials-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.use-credentials-info {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.use-credentials-info > i {
  font-size: 1.5rem;
  color: var(--green-500);
}

.use-credentials-info strong {
  display: block;
  margin-bottom: 0.125rem;
}

.use-credentials-info p {
  margin: 0;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.btn-use-credentials {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.25rem;
  border: none;
  border-radius: 6px;
  background: var(--green-500);
  color: white;
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}

.btn-use-credentials:hover:not(:disabled) {
  background: var(--green-600);
}

.btn-use-credentials:disabled {
  cursor: default;
}

.btn-use-credentials.active {
  background: var(--green-600);
}

.save-profile-form {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}

.profile-name-input {
  padding: 0.625rem 0.875rem;
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  font-size: 0.9rem;
  background: var(--surface-card);
  color: var(--text-color);
  width: 200px;
  transition: border-color 0.15s;
}

.profile-name-input:focus {
  outline: none;
  border-color: var(--primary-color);
}

.profile-name-input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* AWS Profiles Section */
.profiles-section {
  padding: 1.5rem;
  border-bottom: 1px solid var(--surface-border);
  background: var(--surface-ground);
}

.profiles-section h3 {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 0 0 0.5rem 0;
  font-size: 1.1rem;
  color: var(--text-color);
}

.profiles-description {
  margin: 0 0 1rem 0;
  color: var(--text-color-secondary);
  font-size: 0.9rem;
}

.profiles-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0.75rem;
}

.profile-card {
  padding: 1rem;
  background: var(--surface-card);
  border: 2px solid var(--surface-border);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.15s;
}

.profile-card:hover {
  border-color: var(--primary-color);
  background: var(--surface-hover);
}

.profile-card.selected {
  border-color: var(--green-500);
  background: rgba(34, 197, 94, 0.1);
}

.profile-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.profile-header > i {
  color: var(--text-color-secondary);
}

.profile-name {
  flex: 1;
  font-weight: 600;
  color: var(--text-color);
}

.profile-check {
  color: var(--green-500);
}

.btn-delete-profile {
  padding: 0.25rem;
  border: none;
  border-radius: 4px;
  background: transparent;
  color: var(--text-color-secondary);
  cursor: pointer;
  opacity: 0;
  transition: all 0.15s;
}

.profile-card:hover .btn-delete-profile {
  opacity: 1;
}

.btn-delete-profile:hover {
  background: var(--red-100);
  color: var(--red-600);
}

.profile-details {
  margin-top: 0.5rem;
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.profile-region {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.profile-badge {
  padding: 0.125rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.profile-badge.temp {
  background: var(--yellow-100);
  color: var(--yellow-700);
}

.profile-selected-info {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-top: 1rem;
  padding: 0.75rem 1rem;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 6px;
  color: var(--green-700);
}

.profile-selected-info > i {
  color: var(--green-500);
}

.btn-clear-profile {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border: none;
  border-radius: 4px;
  background: transparent;
  color: var(--text-color-secondary);
  font-size: 0.85rem;
  cursor: pointer;
}

.btn-clear-profile:hover {
  background: var(--surface-hover);
  color: var(--text-color);
}

/* Manual Form Toggle */
.manual-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 0;
  color: var(--text-color-secondary);
  cursor: pointer;
  font-size: 0.95rem;
}

.manual-toggle:hover {
  color: var(--text-color);
}

.form-section.collapsed .credential-form,
.form-section.collapsed .form-actions {
  display: none;
}
</style>
