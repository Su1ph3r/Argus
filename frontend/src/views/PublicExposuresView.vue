<template>
  <div class="public-exposures-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Public Exposures</h1>
        <p class="subtitle">
          Internet-exposed resources across cloud environments
        </p>
      </div>
    </div>

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card critical">
        <div class="card-value">
          {{ store.summary.critical }}
        </div>
        <div class="card-label">
          Critical
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.high }}
        </div>
        <div class="card-label">
          High
        </div>
      </div>
      <div class="summary-card medium">
        <div class="card-value">
          {{ store.summary.medium }}
        </div>
        <div class="card-label">
          Medium
        </div>
      </div>
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.internet_exposed }}
        </div>
        <div class="card-label">
          Internet Exposed
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Dropdown
        v-model="filters.exposureType"
        :options="exposureTypes"
        placeholder="Exposure Type"
        class="filter-dropdown"
        @change="applyFilters"
      />
      <Dropdown
        v-model="filters.riskLevel"
        :options="riskLevels"
        placeholder="Risk Level"
        class="filter-dropdown"
        @change="applyFilters"
      />
      <Button
        v-if="hasActiveFilters"
        label="Clear"
        icon="pi pi-times"
        severity="secondary"
        text
        @click="clearFilters"
      />
    </div>

    <DataTable
      :value="store.exposures"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="resource_type"
        header="Resource Type"
      />
      <Column
        field="resource_name"
        header="Resource Name"
      />
      <Column
        field="exposure_type"
        header="Exposure Type"
      />
      <Column
        field="cloud_provider"
        header="Provider"
      />
      <Column
        field="risk_level"
        header="Risk"
      >
        <template #body="{ data }">
          <Tag
            :severity="getRiskSeverity(data.risk_level)"
            :value="data.risk_level"
          />
        </template>
      </Column>
      <Column
        field="is_internet_exposed"
        header="Internet"
      >
        <template #body="{ data }">
          <i :class="data.is_internet_exposed ? 'pi pi-check text-danger' : 'pi pi-minus'" />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            icon="pi pi-eye"
            text
            @click="viewExposure(data)"
          />
        </template>
      </Column>
    </DataTable>

    <Paginator
      v-if="store.pagination.total > store.pagination.pageSize"
      :rows="store.pagination.pageSize"
      :total-records="store.pagination.total"
      :first="(store.pagination.page - 1) * store.pagination.pageSize"
      @page="onPageChange"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { usePublicExposuresStore } from '../stores/publicExposures'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dropdown from 'primevue/dropdown'
import Paginator from 'primevue/paginator'

const store = usePublicExposuresStore()

const filters = ref({
  exposureType: null,
  riskLevel: null,
})

const exposureTypes = ['s3_bucket', 'security_group', 'elb', 'rds', 'api_gateway']
const riskLevels = ['critical', 'high', 'medium', 'low']

const hasActiveFilters = computed(() =>
  Object.values(filters.value).some(v => v !== null),
)

function getRiskSeverity(level) {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[level] || 'secondary'
}

function applyFilters() {
  store.setFilters(filters.value)
}

function clearFilters() {
  filters.value = { exposureType: null, riskLevel: null }
  store.clearFilters()
}

function viewExposure(exposure) {
  console.log('View exposure:', exposure)
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  store.fetchExposures()
}

onMounted(() => {
  store.fetchExposures()
  store.fetchSummary()
})
</script>

<style scoped>
.public-exposures-view {
  padding: 1.5rem;
}
.page-header {
  margin-bottom: 1.5rem;
}
.page-header h1 {
  margin: 0;
  font-size: 1.75rem;
}
.subtitle {
  color: var(--text-color-secondary);
  margin-top: 0.25rem;
}
.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.summary-card {
  padding: 1rem;
  border-radius: 8px;
  background: var(--surface-card);
  border-left: 4px solid;
}
.summary-card.critical { border-left-color: var(--red-500); }
.summary-card.high { border-left-color: var(--orange-500); }
.summary-card.medium { border-left-color: var(--yellow-500); }
.summary-card.info { border-left-color: var(--blue-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section {
  display: flex;
  gap: 1rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}
.filter-dropdown { min-width: 150px; }
.text-danger { color: var(--red-500); }
</style>
