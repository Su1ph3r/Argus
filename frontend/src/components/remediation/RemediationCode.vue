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
  background: #1e1e1e;
}

.code-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-xs) var(--spacing-md);
  background: #2d2d2d;
  border-bottom: 1px solid #3d3d3d;
}

.language-label {
  font-size: 0.75rem;
  color: #888;
  text-transform: uppercase;
}

.code-header :deep(.p-button) {
  color: #888;
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
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 0.8125rem;
  line-height: 1.5;
  color: #d4d4d4;
  white-space: pre-wrap;
  word-break: break-word;
}

/* Basic syntax highlighting classes */
.language-terraform code,
.language-hcl code {
  color: #9cdcfe;
}

.language-bash code,
.language-sh code,
.language-cli code {
  color: #98c379;
}

.language-python code {
  color: #dcdcaa;
}

.language-json code {
  color: #ce9178;
}

.language-yaml code {
  color: #4ec9b0;
}
</style>
