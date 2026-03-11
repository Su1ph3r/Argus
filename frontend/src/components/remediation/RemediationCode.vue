<template>
  <div class="code-container">
    <div
      v-if="showHeader"
      class="code-header"
    >
      <span class="language-label">{{ displayLanguage }}</span>
      <Button
        icon="pi pi-copy"
        size="small"
        text
        title="Copy to clipboard"
        @click="copyCode"
      />
    </div>
    <div class="code-content">
      <pre><code :class="languageClass">{{ code }}</code></pre>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useToast } from 'primevue/usetoast'

const props = defineProps({
  code: {
    type: String,
    required: true,
  },
  language: {
    type: String,
    default: 'bash',
  },
  showHeader: {
    type: Boolean,
    default: false,
  },
})

const toast = useToast()

const languageClass = computed(() => `language-${props.language}`)

const displayLanguage = computed(() => {
  const langMap = {
    terraform: 'Terraform (HCL)',
    aws_cli: 'AWS CLI',
    azure_cli: 'Azure CLI',
    gcloud: 'gcloud',
    kubectl: 'kubectl',
    python: 'Python',
    bash: 'Bash',
    sh: 'Shell',
    powershell: 'PowerShell',
    cli: 'CLI',
    json: 'JSON',
    yaml: 'YAML',
  }
  return langMap[props.language] || props.language
})

const copyCode = async () => {
  try {
    await navigator.clipboard.writeText(props.code)
    toast.add({
      severity: 'success',
      summary: 'Copied',
      detail: 'Code copied to clipboard',
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
.code-container {
  border-radius: var(--radius-sm);
  overflow: hidden;
  background: var(--bg-secondary);
}

.code-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-xs) var(--spacing-md);
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border-color);
}

.language-label {
  font-size: 0.75rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
}

.code-header :deep(.p-button) {
  color: var(--text-tertiary);
}

.code-header :deep(.p-button:hover) {
  color: #fff;
  background: rgba(255, 255, 255, 0.1);
}

.code-content {
  padding: var(--spacing-md);
  overflow-x: auto;
}

.code-content pre {
  margin: 0;
}

.code-content code {
  font-family: 'Source Code Pro', monospace;
  font-size: 0.8125rem;
  line-height: 1.5;
  color: var(--text-primary);
  white-space: pre-wrap;
  word-break: break-word;
}

/* Basic syntax highlighting classes */
.language-terraform code,
.language-hcl code {
  color: var(--accent-primary);
}

.language-bash code,
.language-sh code,
.language-cli code {
  color: var(--text-primary);
}

.language-python code {
  color: var(--accent-primary);
}

.language-json code {
  color: var(--text-secondary);
}

.language-yaml code {
  color: var(--text-primary);
}
</style>
