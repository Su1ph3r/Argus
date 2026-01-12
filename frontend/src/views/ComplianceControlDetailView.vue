<template>
  <div class="control-detail-view">
    <div class="detail-header">
      <Button
        icon="pi pi-arrow-left"
        label="Back to Compliance"
        text
        @click="goBack"
      />
    </div>

    <div
      v-if="complianceStore.controlLoading"
      class="loading"
    >
      <ProgressSpinner />
      <span>Loading control details...</span>
    </div>

    <div
      v-else-if="complianceStore.error"
      class="error"
    >
      <i class="pi pi-exclamation-triangle" />
      {{ complianceStore.error }}
    </div>

    <div
      v-else-if="control"
      class="detail-content"
    >
      <!-- Header Card -->
      <div class="control-header-card card">
        <div class="control-meta">
          <span
            class="status-badge"
            :class="control.status"
          >
            {{ control.status }}
          </span>
          <span
            v-if="control.severity"
            class="severity-badge"
            :class="control.severity"
          >
            {{ control.severity }}
          </span>
          <span class="framework-badge">{{ control.framework }}</span>
        </div>
        <h1>{{ control.control_title || 'Untitled Control' }}</h1>
        <p class="control-id">
          {{ control.control_id }}
        </p>
      </div>

      <!-- Control Details Card -->
      <div class="card">
        <div class="control-detail">
          <!-- Description Section -->
          <div
            v-if="control.control_description"
            class="detail-section"
          >
            <h4>
              <i class="pi pi-file-edit" />
              Description
            </h4>
            <p class="description">
              {{ control.control_description }}
            </p>
          </div>

          <!-- Resource Statistics -->
          <div class="detail-section">
            <h4>
              <i class="pi pi-chart-bar" />
              Resource Compliance
            </h4>
            <div class="stats-grid">
              <div class="stat-card">
                <span class="stat-number">{{ control.total_resources_checked }}</span>
                <span class="stat-label">Resources Checked</span>
              </div>
              <div class="stat-card passed">
                <span class="stat-number">{{ control.resources_passed }}</span>
                <span class="stat-label">Passed</span>
              </div>
              <div class="stat-card failed">
                <span class="stat-number">{{ control.resources_failed }}</span>
                <span class="stat-label">Failed</span>
              </div>
            </div>
          </div>

          <!-- Affected Resources Section -->
          <div
            v-if="control.affected_resources && control.affected_resources.length > 0"
            class="detail-section"
          >
            <h4>
              <i class="pi pi-exclamation-triangle" />
              Affected Resources
              <span class="count-badge">{{ control.affected_resources.length }}</span>
            </h4>
            <div class="affected-resources-list">
              <div
                v-for="(resource, index) in control.affected_resources"
                :key="index"
                class="affected-resource-item"
              >
                <div class="resource-header">
                  <div class="resource-type-badge">{{ resource.resource_type || 'Resource' }}</div>
                  <Tag
                    :severity="resource.status === 'fail' ? 'danger' : 'warn'"
                    :value="resource.status.toUpperCase()"
                    size="small"
                  />
                </div>
                <div class="resource-id">{{ resource.resource_id }}</div>
                <div
                  v-if="resource.resource_name"
                  class="resource-name"
                >
                  {{ resource.resource_name }}
                </div>
                <div class="resource-meta">
                  <span v-if="resource.region">
                    <i class="pi pi-globe" /> {{ resource.region }}
                  </span>
                  <span v-if="resource.account_id">
                    <i class="pi pi-building" /> {{ resource.account_id }}
                  </span>
                </div>
                <div
                  v-if="resource.reason"
                  class="resource-reason"
                >
                  {{ resource.reason }}
                </div>
              </div>
            </div>
          </div>

          <!-- All Compliant Message -->
          <div
            v-else-if="control.status === 'pass'"
            class="detail-section"
          >
            <div class="compliant-message">
              <i class="pi pi-check-circle" />
              <div>
                <strong>All Resources Compliant</strong>
                <p>All resources are compliant with this control.</p>
              </div>
            </div>
          </div>

          <!-- Remediation Section -->
          <div
            v-if="control.remediation_guidance"
            class="detail-section"
          >
            <h4>
              <i class="pi pi-wrench" />
              Remediation Guidance
            </h4>
            <p class="remediation-text">{{ control.remediation_guidance }}</p>

            <!-- CLI Command -->
            <div
              v-if="control.remediation_cli"
              class="cli-section"
            >
              <div class="cli-header">
                <span>AWS CLI Command</span>
                <button
                  class="btn-copy"
                  @click="copyCliCommand"
                >
                  <i class="pi pi-copy" />
                  Copy
                </button>
              </div>
              <pre class="cli-code">{{ control.remediation_cli }}</pre>
            </div>
          </div>

          <!-- Metadata -->
          <div class="detail-section metadata-section">
            <h4>
              <i class="pi pi-info-circle" />
              Metadata
            </h4>
            <div class="detail-grid">
              <div class="detail-item">
                <span class="label">Control ID</span>
                <span class="value code">{{ control.control_id }}</span>
              </div>
              <div class="detail-item">
                <span class="label">Framework</span>
                <span class="value">{{ control.framework }}</span>
              </div>
              <div class="detail-item">
                <span class="label">Status</span>
                <span class="value">{{ control.status.toUpperCase() }}</span>
              </div>
              <div
                v-if="control.severity"
                class="detail-item"
              >
                <span class="label">Severity</span>
                <span class="value">{{ control.severity }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div
      v-else
      class="not-found"
    >
      <i class="pi pi-search" />
      <h2>Control Not Found</h2>
      <p>The requested compliance control could not be found.</p>
      <Button
        label="Go to Compliance"
        @click="goBack"
      />
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useComplianceStore } from '../stores/compliance'

const route = useRoute()
const router = useRouter()
const complianceStore = useComplianceStore()

const control = computed(() => complianceStore.controlDetail)

const goBack = () => {
  const framework = route.params.framework
  if (framework) {
    complianceStore.selectFramework(framework)
  }
  router.push('/compliance')
}

const copyCliCommand = () => {
  if (control.value?.remediation_cli) {
    navigator.clipboard.writeText(control.value.remediation_cli)
  }
}

onMounted(() => {
  const framework = route.params.framework
  const controlId = route.params.controlId
  if (framework && controlId) {
    complianceStore.fetchControlDetails(framework, controlId)
  }
})
</script>

<style scoped>
.control-detail-view {
  max-width: 1000px;
  margin: 0 auto;
}

.detail-header {
  margin-bottom: var(--spacing-lg);
}

.detail-header :deep(.p-button) {
  color: white;
}

.detail-header :deep(.p-button:hover) {
  background: rgba(255, 255, 255, 0.1);
}

.loading,
.not-found {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: calc(var(--spacing-xl) * 2);
  color: white;
  gap: var(--spacing-md);
}

.not-found i {
  font-size: 4rem;
  opacity: 0.5;
}

.not-found h2 {
  margin: 0;
}

.error {
  background: rgba(231, 76, 60, 0.2);
  color: white;
  padding: var(--spacing-lg);
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.detail-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.control-header-card {
  background: var(--card-bg);
  padding: var(--spacing-lg);
  border-radius: var(--radius-lg);
}

.control-meta {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.control-header-card h1 {
  font-size: 1.5rem;
  margin: 0 0 var(--spacing-sm) 0;
  color: white;
}

.control-id {
  font-family: 'Consolas', monospace;
  font-size: 0.875rem;
  color: rgba(255, 255, 255, 0.6);
  margin: 0;
}

.status-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.status-badge.pass {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-badge.fail {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.severity-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.severity-badge.critical {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.severity-badge.high {
  background: rgba(249, 115, 22, 0.2);
  color: #f97316;
}

.severity-badge.medium {
  background: rgba(234, 179, 8, 0.2);
  color: #eab308;
}

.severity-badge.low {
  background: rgba(59, 130, 246, 0.2);
  color: #3b82f6;
}

.framework-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  background: rgba(99, 102, 241, 0.2);
  color: #6366f1;
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 500;
}

.card {
  background: var(--card-bg);
  border-radius: var(--radius-lg);
  border: 1px solid var(--card-border);
}

.control-detail {
  padding: var(--spacing-lg);
}

.detail-section {
  margin-bottom: var(--spacing-xl);
}

.detail-section:last-child {
  margin-bottom: 0;
}

.detail-section h4 {
  font-size: 0.8125rem;
  font-weight: 600;
  color: white;
  margin-bottom: var(--spacing-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding-bottom: var(--spacing-sm);
  border-bottom: 1px solid var(--card-border);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.detail-section h4 i {
  color: var(--primary-color);
  font-size: 0.875rem;
}

.count-badge {
  font-size: 0.7rem;
  padding: 2px 8px;
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
  border-radius: 999px;
  margin-left: var(--spacing-sm);
}

.description {
  color: rgba(255, 255, 255, 0.8);
  line-height: 1.7;
  font-size: 0.9375rem;
  margin: 0;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--spacing-md);
}

.stat-card {
  padding: var(--spacing-lg);
  background: var(--surface-ground);
  border-radius: var(--radius-md);
  text-align: center;
}

.stat-card .stat-number {
  display: block;
  font-size: 2rem;
  font-weight: 700;
  color: white;
}

.stat-card .stat-label {
  display: block;
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.6);
  text-transform: uppercase;
  margin-top: var(--spacing-xs);
}

.stat-card.passed .stat-number {
  color: #22c55e;
}

.stat-card.failed .stat-number {
  color: #ef4444;
}

.affected-resources-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  max-height: 500px;
  overflow-y: auto;
}

.affected-resource-item {
  padding: var(--spacing-md);
  background: var(--surface-ground);
  border: 1px solid var(--card-border);
  border-radius: var(--radius-md);
}

.resource-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.resource-type-badge {
  font-size: 0.7rem;
  color: rgba(255, 255, 255, 0.5);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.resource-id {
  font-family: 'Consolas', monospace;
  font-size: 0.875rem;
  color: white;
  word-break: break-all;
}

.resource-name {
  font-size: 0.875rem;
  color: rgba(255, 255, 255, 0.7);
  margin-top: var(--spacing-xs);
}

.resource-meta {
  display: flex;
  gap: var(--spacing-md);
  margin-top: var(--spacing-sm);
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.5);
}

.resource-meta i {
  margin-right: 0.25rem;
}

.resource-reason {
  margin-top: var(--spacing-sm);
  font-size: 0.8125rem;
  color: rgba(255, 255, 255, 0.6);
  line-height: 1.5;
  padding-top: var(--spacing-sm);
  border-top: 1px solid var(--card-border);
}

.compliant-message {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: var(--radius-md);
}

.compliant-message > i {
  font-size: 2rem;
  color: #22c55e;
}

.compliant-message strong {
  display: block;
  color: white;
  margin-bottom: var(--spacing-xs);
}

.compliant-message p {
  margin: 0;
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.875rem;
}

.remediation-text {
  font-size: 0.9375rem;
  color: rgba(255, 255, 255, 0.8);
  line-height: 1.7;
  margin: 0 0 var(--spacing-md) 0;
}

.cli-section {
  background: var(--surface-ground);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.cli-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-sm) var(--spacing-md);
  background: rgba(0, 0, 0, 0.2);
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.6);
}

.btn-copy {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border: 1px solid var(--card-border);
  border-radius: 4px;
  background: transparent;
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.15s;
}

.btn-copy:hover {
  background: var(--surface-hover);
  color: white;
}

.cli-code {
  margin: 0;
  padding: var(--spacing-md);
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.8125rem;
  color: #22c55e;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.5;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: var(--spacing-sm);
  background: var(--surface-ground);
  border-radius: var(--radius-sm);
}

.detail-item .label {
  font-size: 0.6875rem;
  font-weight: 600;
  color: rgba(255, 255, 255, 0.5);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.detail-item .value {
  color: white;
  font-size: 0.875rem;
  word-break: break-word;
}

.detail-item .value.code {
  font-family: 'Consolas', monospace;
  font-size: 0.8125rem;
}

.metadata-section {
  opacity: 0.9;
}

@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }

  .detail-grid {
    grid-template-columns: 1fr;
  }
}
</style>
