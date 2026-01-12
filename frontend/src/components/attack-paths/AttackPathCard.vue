<template>
  <div
    class="attack-path-card"
    :class="riskClass"
    @click="$emit('view', path)"
  >
    <div class="card-header">
      <div
        class="risk-badge"
        :class="riskClass"
      >
        <span class="risk-score">{{ path.risk_score }}</span>
        <span class="risk-label">Risk</span>
      </div>
      <div class="path-info">
        <h3 class="path-name">
          {{ path.name }}
        </h3>
        <p class="path-description">
          {{ path.description }}
        </p>
      </div>
      <div
        class="card-actions"
        @click.stop
      >
        <Button
          icon="pi pi-copy"
          severity="secondary"
          text
          rounded
          title="Export to clipboard"
          @click="$emit('export', path)"
        />
        <Button
          icon="pi pi-arrow-right"
          severity="secondary"
          text
          rounded
          title="View details"
          @click="$emit('view', path)"
        />
      </div>
    </div>

    <div class="card-body">
      <!-- Path visualization -->
      <div class="path-flow">
        <div class="flow-node entry">
          <i class="pi pi-sign-in" />
          <span>{{ formatEntryPoint(path.entry_point_type) }}</span>
        </div>
        <div class="flow-arrow">
          <span class="hop-count">{{ path.hop_count }} hop{{ path.hop_count !== 1 ? 's' : '' }}</span>
        </div>
        <div class="flow-node target">
          <i class="pi pi-bullseye" />
          <span>{{ formatTarget(path.target_type) }}</span>
        </div>
      </div>

      <!-- Metadata tags -->
      <div class="card-tags">
        <span
          class="tag exploitability"
          :class="path.exploitability"
        >
          {{ path.exploitability }}
        </span>
        <span
          class="tag impact"
          :class="path.impact"
        >
          {{ path.impact }} impact
        </span>
        <span
          v-if="path.poc_available"
          class="tag poc"
        >
          <i class="pi pi-code" /> PoC Available
        </span>
        <span
          v-if="path.requires_authentication"
          class="tag auth"
        >
          <i class="pi pi-lock" /> Auth Required
        </span>
      </div>

      <!-- AWS Services -->
      <div
        v-if="path.aws_services && path.aws_services.length"
        class="services-row"
      >
        <span class="services-label">Services:</span>
        <span
          v-for="service in path.aws_services.slice(0, 5)"
          :key="service"
          class="service-tag"
        >
          {{ service }}
        </span>
        <span
          v-if="path.aws_services.length > 5"
          class="service-more"
        >
          +{{ path.aws_services.length - 5 }} more
        </span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  path: {
    type: Object,
    required: true,
  },
})

defineEmits(['view', 'export'])

const riskClass = computed(() => {
  if (props.path.risk_score >= 80) return 'critical'
  if (props.path.risk_score >= 60) return 'high'
  if (props.path.risk_score >= 40) return 'medium'
  return 'low'
})

const formatEntryPoint = (type) => {
  const labels = {
    'public_s3': 'Public S3',
    'public_lambda': 'Public Lambda',
    'public_ec2': 'Public EC2',
    'public_rds': 'Public RDS',
    'public_security_group': 'Open SG',
    'exposed_credentials': 'Exposed Creds',
    'weak_iam_policy': 'Weak IAM',
  }
  return labels[type] || type
}

const formatTarget = (type) => {
  const labels = {
    'account_takeover': 'Account Takeover',
    'data_exfiltration': 'Data Exfil',
    'persistence': 'Persistence',
    'privilege_escalation': 'Priv Esc',
    'lateral_movement': 'Lateral Move',
  }
  return labels[type] || type
}
</script>

<style scoped>
.attack-path-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.attack-path-card:hover {
  border-color: var(--accent-primary);
  box-shadow: var(--shadow-md);
  transform: translateY(-2px);
}

.attack-path-card.critical {
  border-left: 4px solid var(--severity-critical);
}
.attack-path-card.high {
  border-left: 4px solid var(--severity-high);
}
.attack-path-card.medium {
  border-left: 4px solid var(--severity-medium);
}
.attack-path-card.low {
  border-left: 4px solid var(--severity-low);
}

.card-header {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
}

.risk-badge {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 60px;
  height: 60px;
  border-radius: var(--radius-md);
  flex-shrink: 0;
}

.risk-badge.critical { background: var(--severity-critical-bg); }
.risk-badge.high { background: var(--severity-high-bg); }
.risk-badge.medium { background: var(--severity-medium-bg); }
.risk-badge.low { background: var(--severity-low-bg); }

.risk-badge .risk-score {
  font-size: 1.25rem;
  font-weight: 700;
}

.risk-badge.critical .risk-score { color: var(--severity-critical); }
.risk-badge.high .risk-score { color: var(--severity-high); }
.risk-badge.medium .risk-score { color: var(--severity-medium); }
.risk-badge.low .risk-score { color: var(--severity-low); }

.risk-badge .risk-label {
  font-size: 0.625rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
}

.path-info {
  flex: 1;
  min-width: 0;
}

.path-name {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0 0 var(--spacing-xs) 0;
  line-height: 1.3;
}

.path-description {
  font-size: 0.8125rem;
  color: var(--text-secondary);
  margin: 0;
  line-height: 1.4;
}

.card-actions {
  display: flex;
  gap: var(--spacing-xs);
}

.card-body {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.path-flow {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
}

.flow-node {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--radius-md);
  font-size: 0.8125rem;
  font-weight: 500;
}

.flow-node.entry {
  background: var(--severity-high-bg);
  color: var(--severity-high);
}

.flow-node.target {
  background: var(--severity-critical-bg);
  color: var(--severity-critical);
}

.flow-node i {
  font-size: 0.875rem;
}

.flow-arrow {
  display: flex;
  align-items: center;
  color: var(--text-tertiary);
}

.flow-arrow::before,
.flow-arrow::after {
  content: '';
  width: 20px;
  height: 2px;
  background: var(--border-color);
}

.hop-count {
  padding: 2px 8px;
  font-size: 0.6875rem;
  color: var(--text-secondary);
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  white-space: nowrap;
}

.card-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
}

.tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: var(--radius-full);
  font-size: 0.6875rem;
  font-weight: 600;
  text-transform: uppercase;
}

.tag.exploitability {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
}

.tag.exploitability.confirmed {
  background: var(--severity-critical-bg);
  color: var(--severity-critical);
}

.tag.exploitability.likely {
  background: var(--severity-high-bg);
  color: var(--severity-high);
}

.tag.impact {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
}

.tag.impact.critical {
  background: var(--severity-critical-bg);
  color: var(--severity-critical);
}

.tag.impact.high {
  background: var(--severity-high-bg);
  color: var(--severity-high);
}

.tag.poc {
  background: var(--accent-primary-bg);
  color: var(--accent-primary);
}

.tag.auth {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
}

.services-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--spacing-xs);
}

.services-label {
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-tertiary);
  text-transform: uppercase;
}

.service-tag {
  padding: 2px 8px;
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.service-more {
  font-size: 0.75rem;
  color: var(--text-tertiary);
}

@media (max-width: 640px) {
  .path-flow {
    flex-direction: column;
  }

  .flow-arrow {
    transform: rotate(90deg);
  }

  .flow-arrow::before,
  .flow-arrow::after {
    width: 10px;
  }
}
</style>
