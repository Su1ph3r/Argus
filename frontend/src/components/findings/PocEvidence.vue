<template>
  <div class="poc-evidence">
    <!-- Evidence Text/JSON -->
    <div
      v-if="parsedEvidence"
      class="evidence-block"
    >
      <div class="evidence-header">
        <span>Evidence</span>
        <Button
          icon="pi pi-copy"
          size="small"
          text
          @click="copyToClipboard(evidenceText)"
        />
      </div>
      <div class="code-block">
        <pre>{{ evidenceText }}</pre>
      </div>
    </div>

    <!-- Screenshot -->
    <div
      v-if="finding.poc_screenshot_path"
      class="evidence-block"
    >
      <div class="evidence-header">
        <span>Screenshot</span>
        <a
          :href="screenshotUrl"
          target="_blank"
          class="view-link"
        >
          <i class="pi pi-external-link" /> View Full Size
        </a>
      </div>
      <div class="screenshot-container">
        <img
          :src="screenshotUrl"
          :alt="'Evidence for ' + finding.title"
          @error="handleImageError"
        >
      </div>
    </div>

    <!-- No evidence -->
    <div
      v-if="!hasAnyEvidence"
      class="no-evidence"
    >
      <i class="pi pi-info-circle" />
      No proof of concept evidence available for this finding.
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useToast } from 'primevue/usetoast'

const props = defineProps({
  finding: {
    type: Object,
    required: true,
  },
})

const toast = useToast()
const imageError = ref(false)

const parsedEvidence = computed(() => {
  if (!props.finding.poc_evidence) return null

  // Try to parse as JSON
  try {
    return JSON.parse(props.finding.poc_evidence)
  } catch {
    return props.finding.poc_evidence
  }
})

const evidenceText = computed(() => {
  if (!parsedEvidence.value) return ''

  if (typeof parsedEvidence.value === 'object') {
    return JSON.stringify(parsedEvidence.value, null, 2)
  }
  return parsedEvidence.value
})

const screenshotUrl = computed(() => {
  if (!props.finding.poc_screenshot_path) return ''
  // If path starts with http, use as-is; otherwise prepend /reports/
  if (props.finding.poc_screenshot_path.startsWith('http')) {
    return props.finding.poc_screenshot_path
  }
  return `/reports/${props.finding.poc_screenshot_path}`
})

const hasAnyEvidence = computed(() => {
  return props.finding.poc_evidence ||
         props.finding.poc_screenshot_path
})

const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text)
    toast.add({
      severity: 'success',
      summary: 'Copied',
      detail: 'Copied to clipboard',
      life: 2000,
    })
  } catch (err) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to copy to clipboard',
      life: 3000,
    })
  }
}

const handleImageError = () => {
  imageError.value = true
}
</script>

<style scoped>
.poc-evidence {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.evidence-block {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.evidence-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-sm) var(--spacing-md);
  background: rgba(0, 0, 0, 0.03);
  border-bottom: 1px solid var(--border-color);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-secondary);
}

.evidence-header .view-link {
  font-size: 0.75rem;
  color: var(--gradient-start);
  text-decoration: none;
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
}

.evidence-header .view-link:hover {
  text-decoration: underline;
}

.code-block {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: var(--spacing-md);
  overflow-x: auto;
  font-family: 'Source Code Pro', monospace;
  font-size: 0.8125rem;
  line-height: 1.5;
  max-height: 300px;
  overflow-y: auto;
}

.code-block pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.screenshot-container {
  padding: var(--spacing-md);
  background: var(--bg-primary);
}

.screenshot-container img {
  max-width: 100%;
  height: auto;
  border-radius: var(--radius-sm);
  box-shadow: var(--shadow-sm);
}

.no-evidence {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--bg-primary);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-style: italic;
}
</style>
