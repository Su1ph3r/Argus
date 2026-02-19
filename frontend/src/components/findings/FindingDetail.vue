<template>
  <div class="finding-detail">
    <!-- Detected By Section -->
    <div
      v-if="finding.tool_sources && finding.tool_sources.length > 0"
      class="detail-section tools-section"
    >
      <h4>
        <i class="pi pi-search" />
        Detected By
      </h4>
      <div class="tool-badges">
        <span
          v-for="tool in finding.tool_sources"
          :key="tool"
          class="tool-badge"
        >
          {{ formatToolName(tool) }}
        </span>
      </div>
    </div>

    <!-- Description Section -->
    <div class="detail-section">
      <h4>
        <i class="pi pi-file-edit" />
        Description
      </h4>
      <p class="description">
        {{ finding.description || 'No description available' }}
      </p>
    </div>

    <!-- Resource Details -->
    <div class="detail-section">
      <h4>
        <i class="pi pi-server" />
        Resource Details
      </h4>
      <div class="detail-grid">
        <div class="detail-item">
          <span class="label">Resource Type</span>
          <span class="value">{{ finding.resource_type || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Resource ID</span>
          <span class="value code">{{ finding.resource_id || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Resource Name</span>
          <span class="value">{{ finding.resource_name || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Region</span>
          <span class="value">{{ finding.region || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Account ID</span>
          <span class="value code">{{ finding.account_id || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Tool</span>
          <span class="value">{{ formatToolName(finding.tool) }}</span>
        </div>
      </div>
    </div>

    <!-- Affected Resources Section -->
    <div
      v-if="finding.affected_resources && finding.affected_resources.length > 0"
      class="detail-section"
    >
      <h4>
        <i class="pi pi-list" />
        Affected Resources
        <span class="count-badge">{{ finding.affected_count || finding.affected_resources.length }}</span>
      </h4>
      <div class="affected-resources-list">
        <div
          v-for="(resource, index) in finding.affected_resources"
          :key="index"
          class="affected-resource-item clickable"
          @click="toggleResourcePoc(index)"
        >
          <div class="resource-header">
            <div class="resource-id">
              <i
                class="pi pi-chevron-right"
                :class="{ 'expanded': expandedResources.includes(index) }"
              />
              {{ resource.id }}
            </div>
            <div class="resource-meta">
              <span
                v-if="resource.name && resource.name !== resource.id"
                class="meta-tag"
              >{{ resource.name }}</span>
              <span
                v-if="resource.region"
                class="meta-tag region"
              >{{ resource.region }}</span>
              <span
                v-if="resource.type"
                class="meta-tag type"
              >{{ resource.type }}</span>
            </div>
          </div>
          <div
            v-if="expandedResources.includes(index)"
            class="resource-poc"
            @click.stop
          >
            <h5>Proof of Concept for this Resource</h5>
            <div class="poc-content">
              <pre v-if="resource.poc_output">{{ resource.poc_output }}</pre>
              <p v-else-if="finding.poc_verification">
                <strong>Verification Command:</strong>
                <code>{{ finding.poc_verification.replace('{resource_id}', resource.id) }}</code>
              </p>
              <p
                v-else
                class="no-poc"
              >
                Run verification command to generate PoC for this specific resource.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Verification Command Section (above PoC Evidence) -->
    <div
      v-if="finding.poc_verification"
      class="detail-section"
    >
      <h4>
        <i class="pi pi-terminal" />
        Verification Command
      </h4>
      <VerificationCommand :finding="finding" />
    </div>

    <!-- PoC Evidence Section -->
    <div
      v-if="hasPocEvidenceOnly"
      class="detail-section"
    >
      <h4>
        <i class="pi pi-eye" />
        Proof of Concept Evidence
      </h4>
      <PocEvidence :finding="finding" />
    </div>

    <!-- Remediation Section -->
    <div class="detail-section">
      <h4>
        <i class="pi pi-wrench" />
        Remediation
      </h4>
      <RemediationPanel :finding="finding" />
    </div>

    <!-- Metadata -->
    <div class="detail-section metadata-section">
      <h4>
        <i class="pi pi-info-circle" />
        Metadata
      </h4>
      <div class="detail-grid">
        <div class="detail-item">
          <span class="label">Finding ID</span>
          <span class="value code small">{{ finding.finding_id }}</span>
        </div>
        <div class="detail-item">
          <span class="label">First Seen</span>
          <span class="value">{{ formatDate(finding.first_seen) }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Last Seen</span>
          <span class="value">{{ formatDate(finding.last_seen) }}</span>
        </div>
        <div
          v-if="finding.canonical_id"
          class="detail-item"
        >
          <span class="label">Canonical ID</span>
          <span class="value code small">{{ finding.canonical_id }}</span>
        </div>
        <div
          v-if="finding.cvss_score"
          class="detail-item"
        >
          <span class="label">CVSS Score</span>
          <span class="value">{{ finding.cvss_score }}</span>
        </div>
        <div
          v-if="finding.cve_id"
          class="detail-item"
        >
          <span class="label">CVE</span>
          <a
            :href="`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`"
            target="_blank"
            class="value link"
          >
            {{ finding.cve_id }}
          </a>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import PocEvidence from './PocEvidence.vue'
import VerificationCommand from './VerificationCommand.vue'
import RemediationPanel from '../remediation/RemediationPanel.vue'

const props = defineProps({
  finding: {
    type: Object,
    required: true,
  },
})

// Track which affected resources are expanded
const expandedResources = ref([])

const toggleResourcePoc = (index) => {
  const idx = expandedResources.value.indexOf(index)
  if (idx === -1) {
    expandedResources.value.push(index)
  } else {
    expandedResources.value.splice(idx, 1)
  }
}

// PoC evidence without verification command (shown separately)
const hasPocEvidenceOnly = computed(() => {
  return props.finding.poc_evidence ||
         props.finding.poc_screenshot_path
})

const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A'
  return new Date(dateStr).toLocaleString()
}

const formatToolName = (tool) => {
  if (!tool) return 'Unknown'
  return tool.charAt(0).toUpperCase() + tool.slice(1).replace(/_/g, ' ')
}
</script>

<style scoped>
.finding-detail {
  padding: var(--spacing-lg);
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
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
  color: var(--text-primary);
  margin-bottom: var(--spacing-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding-bottom: var(--spacing-sm);
  border-bottom: 1px solid var(--border-color);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.detail-section h4 i {
  color: var(--accent-primary);
  font-size: 0.875rem;
}

.count-badge {
  font-size: 0.7rem;
  padding: 2px 8px;
  background: var(--accent-primary-bg);
  color: var(--accent-primary);
  border-radius: var(--radius-full);
  margin-left: var(--spacing-sm);
}

.tools-section .tool-badges {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
}

.tool-badge {
  display: inline-flex;
  align-items: center;
  padding: 6px 12px;
  border-radius: var(--radius-md);
  font-size: 0.8125rem;
  font-weight: 500;
  background: var(--accent-primary-bg);
  color: var(--accent-primary);
  border: 1px solid rgba(59, 130, 246, 0.2);
}

.description {
  color: var(--text-primary);
  line-height: 1.7;
  font-size: 0.9375rem;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: var(--spacing-sm);
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
}

.detail-item .label {
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.detail-item .value {
  color: var(--text-primary);
  font-size: 0.875rem;
  word-break: break-word;
}

.detail-item .value.code {
  font-family: 'Source Code Pro', 'Consolas', monospace;
  font-size: 0.8125rem;
  background: var(--bg-card);
  padding: 4px 8px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
}

.detail-item .value.code.small {
  font-size: 0.75rem;
}

.detail-item .value.link {
  color: var(--accent-primary);
  text-decoration: none;
}

.detail-item .value.link:hover {
  text-decoration: underline;
}

.affected-resources-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  max-height: 400px;
  overflow-y: auto;
}

.affected-resource-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
  transition: all var(--transition-fast);
}

.affected-resource-item.clickable {
  cursor: pointer;
}

.affected-resource-item.clickable:hover {
  background: var(--bg-card-hover);
  border-color: var(--accent-primary);
}

.affected-resource-item .resource-header {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.affected-resource-item .resource-id {
  font-family: 'Source Code Pro', 'Consolas', monospace;
  font-size: 0.8125rem;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.affected-resource-item .resource-id i {
  font-size: 0.75rem;
  color: var(--text-tertiary);
  transition: transform var(--transition-fast);
}

.affected-resource-item .resource-id i.expanded {
  transform: rotate(90deg);
}

.affected-resource-item .resource-meta {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
  font-size: 0.75rem;
  margin-left: var(--spacing-lg);
}

.affected-resource-item .meta-tag {
  padding: 2px 8px;
  background: var(--bg-card);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
}

.affected-resource-item .meta-tag.region {
  background: var(--accent-primary-bg);
  color: var(--accent-primary);
}

.affected-resource-item .meta-tag.type {
  background: var(--severity-info-bg);
  color: var(--severity-info);
}

.resource-poc {
  margin-top: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--bg-card);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
}

.resource-poc h5 {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: var(--spacing-sm);
  text-transform: uppercase;
}

.resource-poc .poc-content {
  font-family: 'Source Code Pro', 'Consolas', monospace;
  font-size: 0.75rem;
}

.resource-poc pre {
  background: var(--bg-primary);
  padding: var(--spacing-sm);
  border-radius: var(--radius-sm);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text-primary);
}

.resource-poc code {
  background: var(--bg-primary);
  padding: 2px 6px;
  border-radius: var(--radius-sm);
  color: var(--accent-primary);
}

.resource-poc .no-poc {
  color: var(--text-tertiary);
  font-style: italic;
}

.metadata-section {
  opacity: 0.9;
}
</style>
