<template>
  <div class="filters-container">
    <!-- Severity Quick Filters -->
    <div class="severity-quick-filters">
      <button
        v-for="sev in severityQuickFilters"
        :key="sev.value"
        class="severity-quick-btn"
        :class="[sev.value, { active: selectedSeverities.includes(sev.value) }]"
        @click="toggleSeverity(sev.value)"
      >
        <span class="severity-label">{{ sev.label }}</span>
        <span class="severity-count">{{ findingsStore.summary[sev.value] || 0 }}</span>
      </button>
    </div>

    <div class="filters-row">
      <div class="filter-group">
        <label>Search</label>
        <InputText
          v-model="searchQuery"
          placeholder="Search findings..."
          @input="handleSearchDebounced"
        />
      </div>

      <div class="filter-group">
        <label>Severity</label>
        <MultiSelect
          v-model="selectedSeverities"
          :options="severityOptions"
          option-label="label"
          option-value="value"
          placeholder="All Severities"
          display="chip"
          @change="handleSeverityChange"
        />
      </div>

      <div class="filter-group">
        <label>Status</label>
        <MultiSelect
          v-model="selectedStatuses"
          :options="statusOptions"
          option-label="label"
          option-value="value"
          placeholder="All Statuses"
          display="chip"
          @change="handleStatusChange"
        />
      </div>

      <div class="filter-group">
        <label>Tool</label>
        <Dropdown
          v-model="selectedTool"
          :options="toolOptions"
          option-label="label"
          option-value="value"
          placeholder="All Tools"
          show-clear
          @change="handleToolChange"
        />
      </div>

      <div class="filter-group">
        <label>Provider</label>
        <Dropdown
          v-model="selectedProvider"
          :options="providerOptions"
          option-label="label"
          option-value="value"
          placeholder="All Providers"
          show-clear
          @change="handleProviderChange"
        />
      </div>

      <div class="filter-actions">
        <Button
          v-if="hasFilters"
          label="Clear"
          icon="pi pi-times"
          severity="secondary"
          size="small"
          @click="clearFilters"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useFindingsStore } from '../../stores/findings'

const emit = defineEmits(['filter-change'])
const findingsStore = useFindingsStore()

// Local state
const searchQuery = ref(findingsStore.filters.search || '')
const selectedSeverities = ref(findingsStore.filters.severity ? [findingsStore.filters.severity] : [])
const selectedStatuses = ref(findingsStore.filters.status ? [findingsStore.filters.status] : [])
const selectedTool = ref(findingsStore.filters.tool || null)
const selectedProvider = ref(findingsStore.filters.cloud_provider || null)

// Debounce timer
let searchDebounceTimer = null

// Quick filter buttons
const severityQuickFilters = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
]

// Options
const severityOptions = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
  { label: 'Info', value: 'info' },
]

const statusOptions = [
  { label: 'Open', value: 'open' },
  { label: 'Closed', value: 'closed' },
  { label: 'Mitigated', value: 'mitigated' },
  { label: 'Accepted', value: 'accepted' },
]

const toolOptions = computed(() =>
  findingsStore.filterOptions.tools.map(t => ({ label: t, value: t })),
)

const providerOptions = computed(() =>
  findingsStore.filterOptions.cloudProviders.map(p => ({ label: p, value: p })),
)

const hasFilters = computed(() => findingsStore.hasFilters)

// Handlers
const handleSearchDebounced = () => {
  clearTimeout(searchDebounceTimer)
  searchDebounceTimer = setTimeout(() => {
    findingsStore.setFilter('search', searchQuery.value)
    emit('filter-change')
  }, 300)
}

const handleSeverityChange = () => {
  const value = selectedSeverities.value.length > 0 ? selectedSeverities.value.join(',') : null
  findingsStore.setFilter('severity', value)
  emit('filter-change')
}

const toggleSeverity = (severity) => {
  const idx = selectedSeverities.value.indexOf(severity)
  if (idx === -1) {
    // Add severity
    selectedSeverities.value = [severity]
  } else {
    // Remove severity (clear filter)
    selectedSeverities.value = []
  }
  handleSeverityChange()
}

const handleStatusChange = () => {
  const value = selectedStatuses.value.length > 0 ? selectedStatuses.value.join(',') : null
  findingsStore.setFilter('status', value)
  emit('filter-change')
}

const handleToolChange = () => {
  findingsStore.setFilter('tool', selectedTool.value)
  emit('filter-change')
}

const handleProviderChange = () => {
  findingsStore.setFilter('cloud_provider', selectedProvider.value)
  emit('filter-change')
}

const clearFilters = () => {
  searchQuery.value = ''
  selectedSeverities.value = []
  selectedStatuses.value = []
  selectedTool.value = null
  selectedProvider.value = null
  findingsStore.clearFilters()
  emit('filter-change')
}

// Sync with store when filters change externally
watch(() => findingsStore.filters, (newFilters) => {
  if (newFilters.search !== searchQuery.value) {
    searchQuery.value = newFilters.search || ''
  }
  if (newFilters.severity) {
    selectedSeverities.value = newFilters.severity.split(',')
  }
}, { deep: true })
</script>

<style scoped>
.filters-container {
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
  box-shadow: var(--shadow-md);
}

.filters-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-md);
  align-items: flex-end;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  min-width: 150px;
}

.filter-group label {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
}

.filter-group :deep(.p-inputtext),
.filter-group :deep(.p-dropdown),
.filter-group :deep(.p-multiselect) {
  width: 100%;
}

.filter-actions {
  display: flex;
  align-items: center;
  margin-left: auto;
}

/* Severity Quick Filters */
.severity-quick-filters {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
  flex-wrap: wrap;
}

.severity-quick-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  background: var(--bg-card);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.severity-quick-btn:hover {
  border-color: var(--border-color-light);
}

.severity-quick-btn.active {
  border-width: 2px;
}

.severity-quick-btn.critical {
  border-color: var(--severity-critical-border);
}

.severity-quick-btn.critical.active {
  background: var(--severity-critical-bg);
  border-color: var(--severity-critical);
}

.severity-quick-btn.high {
  border-color: var(--severity-high-border);
}

.severity-quick-btn.high.active {
  background: var(--severity-high-bg);
  border-color: var(--severity-high);
}

.severity-quick-btn.medium {
  border-color: var(--severity-medium-border);
}

.severity-quick-btn.medium.active {
  background: var(--severity-medium-bg);
  border-color: var(--severity-medium);
}

.severity-quick-btn.low {
  border-color: var(--severity-low-border);
}

.severity-quick-btn.low.active {
  background: var(--severity-low-bg);
  border-color: var(--severity-low);
}

.severity-label {
  font-weight: 600;
  font-size: 0.8125rem;
  color: var(--text-primary);
}

.severity-count {
  font-size: 0.75rem;
  padding: 2px 6px;
  border-radius: var(--radius-sm);
  background: var(--bg-tertiary);
  color: var(--text-secondary);
}

.severity-quick-btn.critical .severity-label { color: var(--severity-critical); }
.severity-quick-btn.high .severity-label { color: var(--severity-high); }
.severity-quick-btn.medium .severity-label { color: var(--severity-medium); }
.severity-quick-btn.low .severity-label { color: var(--severity-low); }

@media (max-width: 768px) {
  .filters-row {
    flex-direction: column;
  }

  .filter-group {
    width: 100%;
  }

  .filter-actions {
    width: 100%;
    margin-left: 0;
    justify-content: flex-end;
  }
}
</style>
