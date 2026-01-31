<template>
  <div class="blast-radius-panel">
    <div class="panel-header">
      <h3>
        <i class="pi pi-share-alt" />
        Blast Radius
      </h3>
      <Button
        v-if="!loading && blastRadius"
        icon="pi pi-refresh"
        severity="secondary"
        text
        rounded
        size="small"
        @click="refresh"
      />
    </div>

    <div
      v-if="loading"
      class="loading-state"
    >
      <ProgressSpinner style="width: 24px; height: 24px" />
      <span>Calculating impact...</span>
    </div>

    <div
      v-else-if="error"
      class="error-state"
    >
      <i class="pi pi-exclamation-triangle" />
      <span>{{ error }}</span>
    </div>

    <div
      v-else-if="blastRadius"
      class="blast-content"
    >
      <!-- Impact Summary -->
      <div class="impact-summary">
        <div class="impact-stat">
          <span class="stat-value">{{ blastRadius.total_related_findings }}</span>
          <span class="stat-label">Related Findings</span>
        </div>
        <div class="impact-stat">
          <span class="stat-value">{{ blastRadius.attack_paths_affected }}</span>
          <span class="stat-label">Attack Paths</span>
        </div>
        <div class="impact-stat">
          <span class="stat-value">{{ blastRadius.resources_affected }}</span>
          <span class="stat-label">Resources</span>
        </div>
      </div>

      <!-- Remediation Impact -->
      <div
        v-if="blastRadius.remediation_impact"
        class="remediation-impact"
      >
        <h4>If You Fix This</h4>
        <div class="impact-benefits">
          <div
            v-if="blastRadius.remediation_impact.findings_resolved > 0"
            class="benefit"
          >
            <i class="pi pi-check-circle" />
            <span>{{ blastRadius.remediation_impact.findings_resolved }} findings would be resolved</span>
          </div>
          <div
            v-if="blastRadius.remediation_impact.paths_broken > 0"
            class="benefit"
          >
            <i class="pi pi-shield" />
            <span>{{ blastRadius.remediation_impact.paths_broken }} attack paths would be broken</span>
          </div>
          <div
            v-if="blastRadius.remediation_impact.risk_reduction > 0"
            class="benefit"
          >
            <i class="pi pi-trending-down" />
            <span>{{ blastRadius.remediation_impact.risk_reduction }}% risk reduction</span>
          </div>
        </div>
      </div>

      <!-- Related Resources -->
      <div
        v-if="blastRadius.related_resources?.length > 0"
        class="related-resources"
      >
        <h4>Affected Resources</h4>
        <ul class="resource-list">
          <li
            v-for="resource in blastRadius.related_resources.slice(0, 5)"
            :key="resource.resource_id"
            class="resource-item"
          >
            <span class="resource-type">{{ resource.resource_type }}</span>
            <span class="resource-name">{{ resource.resource_name || resource.resource_id }}</span>
          </li>
        </ul>
        <Button
          v-if="blastRadius.related_resources.length > 5"
          :label="`Show all ${blastRadius.related_resources.length} resources`"
          severity="secondary"
          text
          size="small"
          @click="showAllResources = true"
        />
      </div>

      <!-- Related Findings -->
      <div
        v-if="blastRadius.related_findings?.length > 0"
        class="related-findings"
      >
        <h4>Related Findings</h4>
        <ul class="finding-list">
          <li
            v-for="finding in blastRadius.related_findings.slice(0, 3)"
            :key="finding.id"
            class="finding-item"
          >
            <span
              class="severity-dot"
              :class="finding.severity"
            />
            <span class="finding-title">{{ finding.title }}</span>
          </li>
        </ul>
        <Button
          v-if="blastRadius.related_findings.length > 3"
          :label="`View all ${blastRadius.related_findings.length} related findings`"
          severity="secondary"
          text
          size="small"
          @click="$emit('view-related', blastRadius.related_findings)"
        />
      </div>
    </div>

    <div
      v-else
      class="empty-state"
    >
      <i class="pi pi-info-circle" />
      <span>No blast radius data available</span>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'

const props = defineProps({
  findingId: {
    type: Number,
    required: true,
  },
})

const emit = defineEmits(['view-related'])

// State
const blastRadius = ref(null)
const loading = ref(false)
const error = ref(null)
const showAllResources = ref(false)

// Methods
async function fetchBlastRadius() {
  if (!props.findingId) return

  loading.value = true
  error.value = null

  try {
    const response = await fetch(`/api/blast-radius/findings/${props.findingId}`)
    if (!response.ok) throw new Error('Failed to fetch blast radius')

    blastRadius.value = await response.json()
  } catch (err) {
    error.value = err.message || 'Failed to load blast radius'
    blastRadius.value = null
  } finally {
    loading.value = false
  }
}

function refresh() {
  fetchBlastRadius()
}

// Lifecycle
onMounted(() => {
  fetchBlastRadius()
})

// Watch for finding changes
watch(() => props.findingId, () => {
  fetchBlastRadius()
})
</script>

<style scoped>
.blast-radius-panel {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 1rem;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.panel-header h3 {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 0;
  font-size: 1rem;
}

.loading-state,
.error-state,
.empty-state {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  color: var(--text-color-secondary);
}

.error-state {
  color: var(--red-500);
}

.blast-content {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.impact-summary {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.impact-stat {
  text-align: center;
  padding: 0.75rem;
  background: var(--surface-100);
  border-radius: 6px;
}

.stat-value {
  display: block;
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary-color);
}

.stat-label {
  display: block;
  font-size: 0.75rem;
  color: var(--text-color-secondary);
  text-transform: uppercase;
}

.remediation-impact h4,
.related-resources h4,
.related-findings h4 {
  margin: 0 0 0.75rem 0;
  font-size: 0.875rem;
  color: var(--text-color-secondary);
  text-transform: uppercase;
}

.impact-benefits {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.benefit {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem;
  background: var(--green-50);
  border-radius: 4px;
  color: var(--green-700);
}

.benefit i {
  color: var(--green-500);
}

.resource-list,
.finding-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.resource-item {
  display: flex;
  gap: 0.5rem;
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--surface-100);
}

.resource-item:last-child {
  border-bottom: none;
}

.resource-type {
  font-size: 0.75rem;
  padding: 0.125rem 0.375rem;
  background: var(--surface-200);
  border-radius: 4px;
  color: var(--text-color-secondary);
}

.resource-name {
  font-size: 0.875rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.finding-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0;
}

.severity-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.severity-dot.critical { background: #dc2626; }
.severity-dot.high { background: #ea580c; }
.severity-dot.medium { background: #ca8a04; }
.severity-dot.low { background: #2563eb; }
.severity-dot.info { background: #4f46e5; }

.finding-title {
  font-size: 0.875rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
