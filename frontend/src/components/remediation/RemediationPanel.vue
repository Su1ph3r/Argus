<template>
  <div class="remediation-panel">
    <!-- Basic Remediation Text -->
    <div
      v-if="finding.remediation"
      class="remediation-section"
    >
      <h5>Recommendation</h5>
      <p class="remediation-text">
        {{ finding.remediation }}
      </p>
    </div>

    <!-- Remediation Commands -->
    <div
      v-if="hasCommands"
      class="remediation-section"
    >
      <h5>Remediation Commands</h5>
      <div class="commands-list">
        <div
          v-for="(cmd, index) in finding.remediation_commands"
          :key="index"
          class="command-item"
        >
          <div class="command-header">
            <Tag
              :value="cmd.type || 'command'"
              severity="info"
            />
            <span
              v-if="cmd.description"
              class="command-description"
            >{{ cmd.description }}</span>
            <Button
              icon="pi pi-copy"
              size="small"
              text
              @click="copyToClipboard(cmd.command)"
            />
          </div>
          <RemediationCode
            :code="cmd.command"
            :language="cmd.type"
          />
        </div>
      </div>
    </div>

    <!-- Remediation Code Snippets -->
    <div
      v-if="hasCodeSnippets"
      class="remediation-section"
    >
      <h5>Code Snippets</h5>
      <TabView>
        <TabPanel
          v-for="(code, lang) in finding.remediation_code"
          :key="lang"
          :header="formatLanguage(lang)"
        >
          <RemediationCode
            :code="code"
            :language="lang"
          />
        </TabPanel>
      </TabView>
    </div>

    <!-- External Resources -->
    <div
      v-if="hasResources"
      class="remediation-section"
    >
      <h5>Additional Resources</h5>
      <ul class="resources-list">
        <li
          v-for="(resource, index) in finding.remediation_resources"
          :key="index"
        >
          <a
            :href="resource.url"
            target="_blank"
            rel="noopener noreferrer"
          >
            <i :class="getResourceIcon(resource.type)" />
            {{ resource.title }}
            <i class="pi pi-external-link" />
          </a>
        </li>
      </ul>
    </div>

    <!-- No Remediation Available -->
    <div
      v-if="!hasAnyRemediation"
      class="no-remediation"
    >
      <i class="pi pi-info-circle" />
      No specific remediation guidance available for this finding.
      <p class="suggestion">
        Consider consulting the tool documentation or cloud provider best practices.
      </p>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import RemediationCode from './RemediationCode.vue'

const props = defineProps({
  finding: {
    type: Object,
    required: true,
  },
})

const toast = useToast()

const hasCommands = computed(() => {
  return props.finding.remediation_commands &&
         Array.isArray(props.finding.remediation_commands) &&
         props.finding.remediation_commands.length > 0
})

const hasCodeSnippets = computed(() => {
  return props.finding.remediation_code &&
         typeof props.finding.remediation_code === 'object' &&
         Object.keys(props.finding.remediation_code).length > 0
})

const hasResources = computed(() => {
  return props.finding.remediation_resources &&
         Array.isArray(props.finding.remediation_resources) &&
         props.finding.remediation_resources.length > 0
})

const hasAnyRemediation = computed(() => {
  return props.finding.remediation || hasCommands.value || hasCodeSnippets.value || hasResources.value
})

const formatLanguage = (lang) => {
  const langMap = {
    terraform: 'Terraform',
    aws_cli: 'AWS CLI',
    azure_cli: 'Azure CLI',
    gcloud: 'Google Cloud CLI',
    kubectl: 'kubectl',
    python: 'Python',
    bash: 'Bash',
    powershell: 'PowerShell',
  }
  return langMap[lang] || lang.charAt(0).toUpperCase() + lang.slice(1)
}

const getResourceIcon = (type) => {
  const iconMap = {
    documentation: 'pi pi-book',
    blog: 'pi pi-file',
    video: 'pi pi-video',
    github: 'pi pi-github',
    default: 'pi pi-link',
  }
  return iconMap[type] || iconMap.default
}

const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text)
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
.remediation-panel {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.remediation-section h5 {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  margin-bottom: var(--spacing-sm);
}

.remediation-text {
  color: var(--text-primary);
  line-height: 1.6;
  padding: var(--spacing-md);
  background: var(--bg-secondary);
  border-radius: var(--radius-sm);
  border-left: 3px solid var(--gradient-start);
}

.commands-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.command-item {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.command-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  background: rgba(0, 0, 0, 0.03);
  border-bottom: 1px solid var(--border-color);
}

.command-description {
  flex: 1;
  font-size: 0.8125rem;
  color: var(--text-secondary);
}

.resources-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.resources-list li a {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--bg-secondary);
  border-radius: var(--radius-sm);
  color: var(--gradient-start);
  text-decoration: none;
  transition: background 0.2s ease;
}

.resources-list li a:hover {
  background: rgba(102, 126, 234, 0.1);
}

.resources-list li a .pi-external-link {
  margin-left: auto;
  font-size: 0.75rem;
  opacity: 0.5;
}

.no-remediation {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-lg);
  background: var(--bg-secondary);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  text-align: center;
}

.no-remediation .suggestion {
  font-size: 0.875rem;
  font-style: italic;
}
</style>
