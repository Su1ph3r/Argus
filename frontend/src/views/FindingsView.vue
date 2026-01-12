<template>
  <div class="findings-view">
    <div class="findings-header">
      <div class="header-content">
        <h2>Security Findings</h2>
        <p class="subtitle">
          {{ findingsStore.total }} findings
          <span v-if="findingsStore.hasFilters">(filtered)</span>
        </p>
      </div>
      <div class="header-actions">
        <Button
          label="Export CSV"
          icon="pi pi-download"
          severity="secondary"
          @click="exportCsv"
        />
      </div>
    </div>

    <FindingFilters @filter-change="handleFilterChange" />

    <div
      v-if="findingsStore.error"
      class="error-message"
    >
      <i class="pi pi-exclamation-triangle" />
      {{ findingsStore.error }}
      <Button
        label="Retry"
        size="small"
        @click="loadFindings"
      />
    </div>

    <FindingsTable
      :findings="findingsStore.findings"
      :total="findingsStore.total"
      :page="findingsStore.page"
      :page-size="findingsStore.pageSize"
      :loading="findingsStore.loading"
      :has-filters="findingsStore.hasFilters"
      :sort-field="findingsStore.sortBy"
      :sort-order="findingsStore.sortOrder === 'asc' ? 1 : -1"
      @page-change="handlePageChange"
      @sort-change="handleSortChange"
    />
  </div>
</template>

<script setup>
import { onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useFindingsStore } from '../stores/findings'
import FindingFilters from '../components/findings/FindingFilters.vue'
import FindingsTable from '../components/findings/FindingsTable.vue'

const route = useRoute()
const findingsStore = useFindingsStore()

const loadFindings = () => {
  findingsStore.fetchFindings()
}

const handleFilterChange = () => {
  loadFindings()
}

const handlePageChange = ({ page, pageSize }) => {
  if (pageSize !== findingsStore.pageSize) {
    findingsStore.setPageSize(pageSize)
  }
  if (page !== findingsStore.page) {
    findingsStore.setPage(page)
  }
  loadFindings()
}

const handleSortChange = ({ field, order }) => {
  findingsStore.setSort(field, order)
  loadFindings()
}

const exportCsv = () => {
  // Build export URL with current filters
  const params = new URLSearchParams()
  const filters = findingsStore.filters

  if (filters.severity) params.set('severity', filters.severity)
  if (filters.status) params.set('status', filters.status)
  if (filters.tool) params.set('tool', filters.tool)
  if (filters.cloud_provider) params.set('cloud_provider', filters.cloud_provider)
  params.set('include_remediation', 'true')

  const query = params.toString()
  window.open(`/api/exports/csv${query ? `?${query}` : ''}`, '_blank')
}

// Handle query params for filtering
onMounted(async () => {
  // Fetch summary first to populate filter options (tools, providers)
  await findingsStore.fetchSummary()

  // Check for severity filter in query params (from dashboard click)
  if (route.query.severity) {
    findingsStore.setFilter('severity', route.query.severity)
  }
  loadFindings()
})

// Watch for route query changes
watch(() => route.query, (newQuery) => {
  if (newQuery.severity) {
    findingsStore.setFilter('severity', newQuery.severity)
    loadFindings()
  }
})
</script>

<style scoped>
.findings-view {
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  height: calc(100vh - 180px);
}

.findings-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--spacing-lg);
}

.findings-header h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: white;
  margin: 0;
}

.findings-header .subtitle {
  color: rgba(255, 255, 255, 0.8);
  font-size: 0.875rem;
  margin-top: var(--spacing-xs);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.error-message {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: rgba(231, 76, 60, 0.2);
  color: white;
  border-radius: var(--radius-md);
  margin-bottom: var(--spacing-lg);
}
</style>
