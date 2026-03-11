<template>
  <div class="tool-progress-stepper">
    <div class="progress-summary">
      <span
        v-if="currentTool"
        class="current-tool"
      >
        Running {{ formatToolName(currentTool) }}
      </span>
      <span class="progress-count">
        ({{ completedTools.length }}/{{ tools.length }} completed)
      </span>
    </div>
    <div class="stepper-list">
      <div
        v-for="(tool, index) in tools"
        :key="tool"
        class="step-item"
        :class="getStepClass(tool)"
      >
        <div
          v-if="index > 0"
          class="step-connector"
        />
        <div class="step-icon">
          <i :class="getStepIcon(tool)" />
        </div>
        <div class="step-content">
          <span class="step-label">{{ formatToolName(tool) }}</span>
          <span
            v-if="toolErrors[tool]"
            class="step-error"
          >Failed</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
const props = defineProps({
  tools: {
    type: Array,
    required: true,
    default: () => [],
  },
  completedTools: {
    type: Array,
    default: () => [],
  },
  toolErrors: {
    type: Object,
    default: () => ({}),
  },
  currentTool: {
    type: String,
    default: null,
  },
  scanStatus: {
    type: String,
    default: 'running',
  },
})

const toolNameMap = {
  prowler: 'Prowler',
  scoutsuite: 'ScoutSuite',
  cloudfox: 'CloudFox',
  cloudsploit: 'CloudSploit',
  'cloud-custodian': 'Cloud Custodian',
  cartography: 'Cartography',
  pacu: 'Pacu',
  'enumerate-iam': 'enumerate-iam',
  kubescape: 'Kubescape',
  checkov: 'Checkov',
  terrascan: 'Terrascan',
  tfsec: 'tfsec',
}

function formatToolName(tool) {
  return toolNameMap[tool] || tool.charAt(0).toUpperCase() + tool.slice(1)
}

function getStepClass(tool) {
  if (props.completedTools.includes(tool)) {
    return 'completed'
  }
  if (props.toolErrors[tool]) {
    return 'failed'
  }
  if (tool === props.currentTool) {
    return 'running'
  }
  return 'pending'
}

function getStepIcon(tool) {
  if (props.completedTools.includes(tool)) {
    return 'pi pi-check-circle'
  }
  if (props.toolErrors[tool]) {
    return 'pi pi-times-circle'
  }
  if (tool === props.currentTool) {
    return 'pi pi-spin pi-spinner'
  }
  return 'pi pi-circle'
}
</script>

<style scoped>
.tool-progress-stepper {
  padding: 1rem;
}

.progress-summary {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
  font-size: 0.95rem;
}

.current-tool {
  font-weight: 600;
  color: var(--accent-primary, #E0F2FE);
}

.progress-count {
  color: var(--text-secondary, #9BA0BE);
}

.stepper-list {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.step-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0;
  position: relative;
}

.step-connector {
  position: absolute;
  left: 0.5rem;
  top: -0.5rem;
  width: 2px;
  height: 1rem;
  background-color: var(--border-color, #1A1D2E);
}

.step-item.completed .step-connector {
  background-color: var(--status-closed, #059669);
}

.step-item.running .step-connector {
  background-color: var(--accent-primary, #E0F2FE);
}

.step-item.failed .step-connector {
  background-color: var(--severity-critical, #EF4444);
}

.step-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 1.25rem;
  flex-shrink: 0;
}

.step-icon i {
  font-size: 1rem;
}

.step-item.completed .step-icon i {
  color: var(--status-closed, #059669);
}

.step-item.running .step-icon i {
  color: var(--accent-primary, #E0F2FE);
}

.step-item.failed .step-icon i {
  color: var(--severity-critical, #EF4444);
}

.step-item.pending .step-icon i {
  color: var(--text-secondary, #9BA0BE);
}

.step-content {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.step-label {
  font-size: 0.875rem;
}

.step-item.completed .step-label {
  color: var(--status-closed, #059669);
}

.step-item.running .step-label {
  color: var(--accent-primary, #E0F2FE);
  font-weight: 500;
}

.step-item.failed .step-label {
  color: var(--severity-critical, #EF4444);
}

.step-item.pending .step-label {
  color: var(--text-secondary, #9BA0BE);
}

.step-error {
  font-size: 0.75rem;
  color: var(--severity-critical, #EF4444);
  background-color: var(--severity-critical-bg, rgba(239, 68, 68, 0.1));
  padding: 0.125rem 0.375rem;
  border-radius: 0.25rem;
}
</style>
