<template>
  <div class="iac-upload">
    <div class="upload-header">
      <h3>IaC Security Scanning</h3>
      <p class="description">
        Upload Terraform, CloudFormation, Kubernetes manifests, or Helm charts for security analysis.
      </p>
    </div>

    <!-- File Upload Area -->
    <div
      class="upload-dropzone"
      :class="{ 'drag-over': isDragOver, 'has-files': uploadedFiles.length > 0 }"
      @dragover.prevent="isDragOver = true"
      @dragleave.prevent="isDragOver = false"
      @drop.prevent="handleDrop"
    >
      <input
        ref="fileInput"
        type="file"
        multiple
        :accept="acceptedExtensions"
        class="file-input"
        @change="handleFileSelect"
      >

      <div
        v-if="uploadedFiles.length === 0"
        class="upload-placeholder"
        @click="$refs.fileInput.click()"
      >
        <i class="pi pi-cloud-upload upload-icon" />
        <span class="upload-text">Drop files here or click to upload</span>
        <span class="upload-hint">Supported: .tf, .tfvars, .yaml, .yml, .json, .hcl, .tpl, .zip</span>
      </div>

      <div
        v-else
        class="uploaded-files"
      >
        <div class="files-header">
          <span class="file-count">{{ uploadedFiles.length }} file(s) selected</span>
          <Button
            icon="pi pi-plus"
            text
            size="small"
            label="Add More"
            @click="$refs.fileInput.click()"
          />
        </div>
        <div class="file-list">
          <div
            v-for="(file, index) in uploadedFiles"
            :key="index"
            class="file-item"
          >
            <i :class="getFileIcon(file.name)" />
            <span class="file-name">{{ file.name }}</span>
            <span class="file-size">{{ formatFileSize(file.size) }}</span>
            <Button
              icon="pi pi-times"
              text
              severity="secondary"
              size="small"
              @click="removeFile(index)"
            />
          </div>
        </div>
        <Button
          label="Clear All"
          icon="pi pi-trash"
          text
          severity="danger"
          size="small"
          class="clear-btn"
          @click="clearFiles"
        />
      </div>
    </div>

    <!-- Profile Selection -->
    <div class="profile-selection">
      <label>Scan Profile</label>
      <Dropdown
        v-model="selectedProfile"
        :options="profiles"
        option-label="name"
        option-value="name"
        placeholder="Select a scan profile"
        class="w-full"
      >
        <template #option="{ option }">
          <div class="profile-option">
            <span class="profile-name">{{ option.name }}</span>
            <span class="profile-desc">{{ option.description }}</span>
          </div>
        </template>
      </Dropdown>
      <div
        v-if="selectedProfileDetails"
        class="profile-info"
      >
        <div class="profile-tools">
          <span class="tools-label">Tools:</span>
          <Tag
            v-for="tool in selectedProfileDetails.tools"
            :key="tool"
            :value="formatToolName(tool)"
            severity="info"
            class="tool-tag"
          />
        </div>
        <div class="profile-frameworks">
          <span class="frameworks-label">Supported:</span>
          <span>{{ selectedProfileDetails.supported_frameworks.join(', ') }}</span>
        </div>
      </div>
    </div>

    <!-- Upload Progress -->
    <div
      v-if="uploading"
      class="upload-progress"
    >
      <ProgressBar :value="uploadProgress" />
      <span class="progress-text">Uploading files...</span>
    </div>

    <!-- Scan Progress -->
    <div
      v-if="scanStarted && currentScanId"
      class="scan-status"
    >
      <i class="pi pi-spin pi-spinner" />
      <span>Scan started. Redirecting to scan details...</span>
    </div>

    <!-- Action Buttons -->
    <div class="upload-actions">
      <Button
        label="Cancel"
        text
        @click="$emit('cancel')"
      />
      <Button
        label="Upload & Scan"
        icon="pi pi-play"
        :disabled="uploadedFiles.length === 0 || !selectedProfile || uploading || scanStarted"
        :loading="uploading || scanStarted"
        @click="uploadAndScan"
      />
    </div>

    <!-- Error Display -->
    <Message
      v-if="errorMessage"
      severity="error"
      :closable="true"
      @close="errorMessage = ''"
    >
      {{ errorMessage }}
    </Message>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import ProgressBar from 'primevue/progressbar'
import Tag from 'primevue/tag'
import Message from 'primevue/message'
import { api } from '../../services/api'
import { toast } from '../../services/toast'

const emit = defineEmits(['cancel', 'scan-started'])
const router = useRouter()

const fileInput = ref(null)
const uploadedFiles = ref([])
const selectedProfile = ref(null)
const profiles = ref([])
const isDragOver = ref(false)
const uploading = ref(false)
const uploadProgress = ref(0)
const scanStarted = ref(false)
const currentScanId = ref(null)
const errorMessage = ref('')

const acceptedExtensions = '.tf,.tfvars,.hcl,.yaml,.yml,.json,.tpl,.zip'

const selectedProfileDetails = computed(() => {
  if (!selectedProfile.value) return null
  return profiles.value.find(p => p.name === selectedProfile.value)
})

function formatToolName(tool) {
  return tool
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

function getFileIcon(filename) {
  const ext = filename.split('.').pop().toLowerCase()
  const icons = {
    tf: 'pi pi-file',
    tfvars: 'pi pi-file',
    hcl: 'pi pi-file',
    yaml: 'pi pi-file',
    yml: 'pi pi-file',
    json: 'pi pi-file',
    tpl: 'pi pi-file',
    zip: 'pi pi-file-export',
  }
  return icons[ext] || 'pi pi-file'
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

function handleDrop(event) {
  isDragOver.value = false
  const files = Array.from(event.dataTransfer.files)
  addFiles(files)
}

function handleFileSelect(event) {
  const files = Array.from(event.target.files)
  addFiles(files)
  // Reset input so same file can be selected again
  event.target.value = ''
}

function addFiles(files) {
  const validExtensions = acceptedExtensions.split(',').map(ext => ext.toLowerCase())

  for (const file of files) {
    const ext = '.' + file.name.split('.').pop().toLowerCase()
    if (validExtensions.includes(ext)) {
      // Check for duplicates
      if (!uploadedFiles.value.some(f => f.name === file.name)) {
        uploadedFiles.value.push(file)
      }
    } else {
      toast.warning(`Skipped ${file.name}: unsupported file type`)
    }
  }
}

function removeFile(index) {
  uploadedFiles.value.splice(index, 1)
}

function clearFiles() {
  uploadedFiles.value = []
}

async function uploadAndScan() {
  if (uploadedFiles.value.length === 0 || !selectedProfile.value) return

  try {
    uploading.value = true
    uploadProgress.value = 0
    errorMessage.value = ''

    // Upload files
    const uploadResult = await api.uploadIaCFiles(uploadedFiles.value, progress => {
      uploadProgress.value = progress
    })

    uploadProgress.value = 100
    uploading.value = false
    scanStarted.value = true
    currentScanId.value = uploadResult.scan_id

    toast.success(`Uploaded ${uploadResult.files_uploaded} file(s) successfully`)

    // Start scan
    const scanResult = await api.startIaCScan(uploadResult.scan_id, selectedProfile.value)

    toast.success(`IaC scan started with profile "${selectedProfile.value}"`)
    emit('scan-started', scanResult.scan_id)

    // Navigate to scan details
    setTimeout(() => {
      router.push(`/scans/${scanResult.scan_id}`)
    }, 1000)

  } catch (error) {
    console.error('IaC upload/scan failed:', error)
    errorMessage.value = error.message || 'Failed to upload files or start scan'
    toast.apiError(error, 'IaC scanning failed')
    uploading.value = false
    scanStarted.value = false
  }
}

async function fetchProfiles() {
  try {
    const result = await api.getIaCProfiles()
    profiles.value = result.profiles || []
    // Default to iac-quick
    if (profiles.value.length > 0) {
      selectedProfile.value = profiles.value[0].name
    }
  } catch (error) {
    console.error('Failed to fetch IaC profiles:', error)
    toast.apiError(error, 'Failed to load IaC scan profiles')
  }
}

onMounted(() => {
  fetchProfiles()
})
</script>

<style scoped>
.iac-upload {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.upload-header h3 {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: 1.125rem;
}

.description {
  color: var(--text-secondary);
  font-size: 0.875rem;
  margin: 0;
}

/* Dropzone */
.upload-dropzone {
  border: 2px dashed var(--border-color);
  border-radius: var(--radius-lg);
  transition: all var(--transition-normal);
  min-height: 200px;
  position: relative;
}

.upload-dropzone.drag-over {
  border-color: var(--primary-color);
  background: var(--primary-50);
}

.upload-dropzone.has-files {
  border-style: solid;
}

.file-input {
  display: none;
}

.upload-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  cursor: pointer;
  height: 100%;
  min-height: 200px;
}

.upload-icon {
  font-size: 3rem;
  color: var(--primary-color);
  margin-bottom: var(--spacing-md);
}

.upload-text {
  font-size: 1rem;
  font-weight: 500;
  margin-bottom: var(--spacing-xs);
}

.upload-hint {
  font-size: 0.8125rem;
  color: var(--text-secondary);
}

/* Uploaded Files */
.uploaded-files {
  padding: var(--spacing-md);
}

.files-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.file-count {
  font-weight: 500;
  color: var(--text-secondary);
}

.file-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  max-height: 200px;
  overflow-y: auto;
}

.file-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
}

.file-item i {
  color: var(--text-secondary);
}

.file-name {
  flex: 1;
  font-size: 0.875rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-size {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.clear-btn {
  margin-top: var(--spacing-sm);
}

/* Profile Selection */
.profile-selection {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.profile-selection label {
  font-weight: 500;
  font-size: 0.875rem;
}

.profile-option {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.profile-name {
  font-weight: 500;
}

.profile-desc {
  font-size: 0.8125rem;
  color: var(--text-secondary);
}

.profile-info {
  padding: var(--spacing-sm);
  background: var(--bg-tertiary);
  border-radius: var(--radius-md);
  font-size: 0.875rem;
}

.profile-tools,
.profile-frameworks {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

.profile-frameworks {
  margin-top: var(--spacing-xs);
}

.tools-label,
.frameworks-label {
  color: var(--text-secondary);
  font-size: 0.8125rem;
}

.tool-tag {
  font-size: 0.75rem;
}

/* Progress */
.upload-progress,
.scan-status {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--bg-tertiary);
  border-radius: var(--radius-md);
}

.scan-status {
  flex-direction: row;
  color: var(--primary-color);
}

.progress-text {
  font-size: 0.875rem;
  color: var(--text-secondary);
}

/* Actions */
.upload-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  padding-top: var(--spacing-md);
  border-top: 1px solid var(--border-color);
}

.w-full {
  width: 100%;
}
</style>
