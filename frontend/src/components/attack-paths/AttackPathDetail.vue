<template>
  <div class="attack-path-detail">
    <!-- Overview Section -->
    <div class="detail-section">
      <div class="overview-grid">
        <div class="overview-item">
          <span class="item-label">Risk Score</span>
          <span
            class="item-value risk-score"
            :class="riskClass"
          >{{ path.risk_score }}/100</span>
        </div>
        <div class="overview-item">
          <span class="item-label">Exploitability</span>
          <span
            class="item-value tag"
            :class="path.exploitability"
          >{{ path.exploitability }}</span>
        </div>
        <div class="overview-item">
          <span class="item-label">Impact</span>
          <span
            class="item-value tag"
            :class="path.impact"
          >{{ path.impact }}</span>
        </div>
        <div class="overview-item">
          <span class="item-label">Hops</span>
          <span class="item-value">{{ path.hop_count }}</span>
        </div>
      </div>
    </div>

    <!-- Path Visualization -->
    <div class="detail-section">
      <h4>
        <i class="pi pi-sitemap" />
        Attack Chain
      </h4>
      <div class="path-visualization">
        <div
          v-for="(node, index) in path.nodes"
          :key="node.id"
          class="path-step"
        >
          <div
            class="step-node"
            :class="node.type"
          >
            <div class="node-icon">
              <i :class="getNodeIcon(node.type)" />
            </div>
            <div class="node-info">
              <span class="node-name">{{ node.name }}</span>
              <span
                v-if="node.resource_id"
                class="node-resource"
              >{{ node.resource_id }}</span>
              <span
                v-if="node.region"
                class="node-region"
              >{{ node.region }}</span>
            </div>
          </div>
          <div
            v-if="index < path.nodes.length - 1"
            class="step-connector"
          >
            <div class="connector-line" />
            <div
              v-if="path.edges[index]"
              class="connector-label"
            >
              {{ path.edges[index].name }}
            </div>
            <div class="connector-arrow">
              <i class="pi pi-arrow-down" />
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- PoC Steps -->
    <div
      v-if="path.poc_steps && path.poc_steps.length"
      class="detail-section"
    >
      <h4>
        <i class="pi pi-code" />
        Proof of Concept Steps
      </h4>
      <div class="poc-steps">
        <div
          v-for="step in path.poc_steps"
          :key="step.step"
          class="poc-step"
        >
          <div class="step-header">
            <span class="step-number">Step {{ step.step }}</span>
            <span class="step-name">{{ step.name }}</span>
            <span
              v-if="step.requires_auth"
              class="auth-badge"
            >
              <i class="pi pi-lock" /> Auth Required
            </span>
          </div>
          <p class="step-description">
            {{ step.description }}
          </p>
          <div class="step-command">
            <code>{{ step.command }}</code>
            <Button
              icon="pi pi-copy"
              severity="secondary"
              text
              rounded
              size="small"
              @click="copyCommand(step.command)"
            />
          </div>
          <div
            v-if="step.mitre_technique"
            class="step-mitre"
          >
            MITRE ATT&CK: {{ step.mitre_technique }}
          </div>
        </div>
      </div>
    </div>

    <!-- MITRE ATT&CK Mapping -->
    <div
      v-if="path.mitre_tactics && path.mitre_tactics.length"
      class="detail-section"
    >
      <h4>
        <i class="pi pi-shield" />
        MITRE ATT&CK Tactics
      </h4>
      <div class="mitre-tags">
        <span
          v-for="tactic in path.mitre_tactics"
          :key="tactic"
          class="mitre-tag"
        >
          {{ formatMitreTactic(tactic) }}
        </span>
      </div>
    </div>

    <!-- AWS Services -->
    <div
      v-if="path.aws_services && path.aws_services.length"
      class="detail-section"
    >
      <h4>
        <i class="pi pi-cloud" />
        Affected AWS Services
      </h4>
      <div class="service-tags">
        <span
          v-for="service in path.aws_services"
          :key="service"
          class="service-tag"
        >
          {{ service }}
        </span>
      </div>
    </div>

    <!-- Associated Findings -->
    <div
      v-if="path.finding_ids && path.finding_ids.length"
      class="detail-section"
    >
      <h4>
        <i class="pi pi-list" />
        Related Findings
      </h4>
      <div class="findings-list">
        <div
          v-for="id in path.finding_ids"
          :key="id"
          class="finding-link"
        >
          <router-link :to="`/findings/${id}`">
            Finding #{{ id }}
          </router-link>
        </div>
      </div>
    </div>

    <!-- Export Actions -->
    <div class="detail-actions">
      <Button
        label="Export as Markdown"
        icon="pi pi-file-edit"
        severity="secondary"
        @click="$emit('export', path)"
      />
      <Button
        label="Copy All Commands"
        icon="pi pi-copy"
        severity="secondary"
        @click="copyAllCommands"
      />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useToast } from 'primevue/usetoast'

const props = defineProps({
  path: {
    type: Object,
    required: true,
  },
})

defineEmits(['export'])

const toast = useToast()

const riskClass = computed(() => {
  if (props.path.risk_score >= 80) return 'critical'
  if (props.path.risk_score >= 60) return 'high'
  if (props.path.risk_score >= 40) return 'medium'
  return 'low'
})

const getNodeIcon = (type) => {
  const icons = {
    'entry_point': 'pi pi-sign-in',
    'resource': 'pi pi-server',
    'target': 'pi pi-bullseye',
  }
  return icons[type] || 'pi pi-circle'
}

const formatMitreTactic = (tactic) => {
  const labels = {
    'TA0001': 'Initial Access',
    'TA0002': 'Execution',
    'TA0003': 'Persistence',
    'TA0004': 'Privilege Escalation',
    'TA0005': 'Defense Evasion',
    'TA0006': 'Credential Access',
    'TA0007': 'Discovery',
    'TA0008': 'Lateral Movement',
    'TA0009': 'Collection',
    'TA0010': 'Exfiltration',
    'TA0011': 'Command and Control',
  }
  return labels[tactic] || tactic
}

const copyCommand = async (command) => {
  try {
    await navigator.clipboard.writeText(command)
    toast.add({
      severity: 'success',
      summary: 'Copied',
      detail: 'Command copied to clipboard',
      life: 2000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Failed',
      detail: 'Could not copy to clipboard',
      life: 2000,
    })
  }
}

const copyAllCommands = async () => {
  if (!props.path.poc_steps?.length) return

  const commands = props.path.poc_steps
    .map(step => `# Step ${step.step}: ${step.name}\n${step.command}`)
    .join('\n\n')

  try {
    await navigator.clipboard.writeText(commands)
    toast.add({
      severity: 'success',
      summary: 'Copied',
      detail: 'All commands copied to clipboard',
      life: 2000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Failed',
      detail: 'Could not copy to clipboard',
      life: 2000,
    })
  }
}
</script>

<style scoped>
.attack-path-detail {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.detail-section h4 {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-sm);
  border-bottom: 1px solid var(--border-color);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.detail-section h4 i {
  color: var(--accent-primary);
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
}

.overview-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: var(--spacing-md);
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  text-align: center;
}

.item-label {
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-tertiary);
  text-transform: uppercase;
}

.item-value {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-primary);
}

.item-value.risk-score.critical { color: var(--severity-critical); }
.item-value.risk-score.high { color: var(--severity-high); }
.item-value.risk-score.medium { color: var(--severity-medium); }
.item-value.risk-score.low { color: var(--severity-low); }

.item-value.tag {
  display: inline-block;
  padding: 4px 12px;
  border-radius: var(--radius-full);
  font-size: 0.75rem;
  text-transform: capitalize;
}

.item-value.tag.confirmed { background: var(--severity-critical-bg); color: var(--severity-critical); }
.item-value.tag.likely { background: var(--severity-high-bg); color: var(--severity-high); }
.item-value.tag.theoretical { background: var(--bg-tertiary); color: var(--text-secondary); }
.item-value.tag.critical { background: var(--severity-critical-bg); color: var(--severity-critical); }
.item-value.tag.high { background: var(--severity-high-bg); color: var(--severity-high); }
.item-value.tag.medium { background: var(--severity-medium-bg); color: var(--severity-medium); }
.item-value.tag.low { background: var(--severity-low-bg); color: var(--severity-low); }

.path-visualization {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: var(--spacing-lg);
  background: var(--bg-secondary);
  border-radius: var(--radius-lg);
}

.path-step {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  max-width: 400px;
}

.step-node {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  width: 100%;
  padding: var(--spacing-md);
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
}

.step-node.entry_point {
  border-color: var(--severity-high);
  background: var(--severity-high-bg);
}

.step-node.target {
  border-color: var(--severity-critical);
  background: var(--severity-critical-bg);
}

.node-icon {
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-tertiary);
  border-radius: var(--radius-md);
  font-size: 1.25rem;
  color: var(--text-secondary);
}

.step-node.entry_point .node-icon { background: var(--severity-high); color: white; }
.step-node.target .node-icon { background: var(--severity-critical); color: white; }

.node-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
  min-width: 0;
}

.node-name {
  font-weight: 600;
  color: var(--text-primary);
}

.node-resource {
  font-family: 'Source Code Pro', monospace;
  font-size: 0.75rem;
  color: var(--text-secondary);
  word-break: break-all;
}

.node-region {
  font-size: 0.6875rem;
  color: var(--text-tertiary);
}

.step-connector {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: var(--spacing-sm) 0;
}

.connector-line {
  width: 2px;
  height: 20px;
  background: var(--border-color);
}

.connector-label {
  padding: 4px 12px;
  background: var(--bg-tertiary);
  border-radius: var(--radius-full);
  font-size: 0.6875rem;
  color: var(--text-secondary);
  text-align: center;
}

.connector-arrow {
  color: var(--text-tertiary);
  font-size: 0.75rem;
}

.poc-steps {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.poc-step {
  padding: var(--spacing-md);
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  border-left: 3px solid var(--accent-primary);
}

.step-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.step-number {
  font-size: 0.6875rem;
  font-weight: 700;
  padding: 2px 8px;
  background: var(--accent-primary);
  color: white;
  border-radius: var(--radius-sm);
  text-transform: uppercase;
}

.step-name {
  font-weight: 600;
  color: var(--text-primary);
}

.auth-badge {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  padding: 2px 8px;
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  border-radius: var(--radius-full);
}

.step-description {
  font-size: 0.875rem;
  color: var(--text-secondary);
  margin-bottom: var(--spacing-sm);
}

.step-command {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--bg-primary);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
}

.step-command code {
  flex: 1;
  font-family: 'Source Code Pro', monospace;
  font-size: 0.8125rem;
  color: var(--accent-primary);
  word-break: break-all;
  white-space: pre-wrap;
}

.step-mitre {
  margin-top: var(--spacing-sm);
  font-size: 0.6875rem;
  color: var(--text-tertiary);
}

.mitre-tags,
.service-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
}

.mitre-tag {
  padding: 6px 12px;
  background: var(--accent-primary-bg);
  color: var(--accent-primary);
  border-radius: var(--radius-md);
  font-size: 0.8125rem;
  font-weight: 500;
}

.service-tag {
  padding: 6px 12px;
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  border-radius: var(--radius-md);
  font-size: 0.8125rem;
}

.findings-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
}

.finding-link a {
  display: inline-block;
  padding: 4px 12px;
  background: var(--bg-secondary);
  color: var(--accent-primary);
  border-radius: var(--radius-md);
  font-size: 0.875rem;
  text-decoration: none;
  transition: all var(--transition-fast);
}

.finding-link a:hover {
  background: var(--accent-primary-bg);
}

.detail-actions {
  display: flex;
  gap: var(--spacing-md);
  padding-top: var(--spacing-lg);
  border-top: 1px solid var(--border-color);
}

@media (max-width: 768px) {
  .overview-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .detail-actions {
    flex-direction: column;
  }
}
</style>
