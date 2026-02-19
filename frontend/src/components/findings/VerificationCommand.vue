<template>
  <div
    v-if="finding.poc_verification"
    class="verification-command"
  >
    <div class="command-header">
      <span class="command-label">Verification Command</span>
      <Button
        icon="pi pi-copy"
        size="small"
        text
        title="Copy to clipboard"
        @click="copyToClipboard"
      />
    </div>
    <div class="command-block">
      <code>{{ finding.poc_verification }}</code>
    </div>
  </div>
</template>

<script setup>
import { useToast } from 'primevue/usetoast'

const props = defineProps({
  finding: {
    type: Object,
    required: true,
  },
})

const toast = useToast()

const copyToClipboard = async () => {
  try {
    await navigator.clipboard.writeText(props.finding.poc_verification)
    toast.add({
      severity: 'success',
      summary: 'Copied',
      detail: 'Command copied to clipboard',
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
</script>

<style scoped>
.verification-command {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  overflow: hidden;
  background: var(--bg-tertiary);
}

.command-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-sm) var(--spacing-md);
  background: rgba(0, 0, 0, 0.05);
  border-bottom: 1px solid var(--border-color);
}

.command-label {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-secondary);
  letter-spacing: 0.03em;
}

.command-block {
  background: #1e1e1e;
  padding: var(--spacing-md);
  overflow-x: auto;
}

.command-block code {
  font-family: 'Source Code Pro', 'Consolas', monospace;
  font-size: 0.8125rem;
  line-height: 1.6;
  color: #98c379;
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
