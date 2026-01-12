<template>
  <div class="exposed-credentials-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Exposed Credentials</h1>
        <p class="subtitle">
          Credentials discovered in scan data
        </p>
      </div>
    </div>

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card critical">
        <div class="card-value">
          {{ store.summary.total }}
        </div>
        <div class="card-label">
          Total
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.active }}
        </div>
        <div class="card-label">
          Active
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Dropdown
        v-model="filters.credentialType"
        :options="credentialTypes"
        placeholder="Credential Type"
        class="filter-dropdown"
        @change="applyFilters"
      />
      <Dropdown
        v-model="filters.sourceType"
        :options="sourceTypes"
        placeholder="Source Type"
        class="filter-dropdown"
        @change="applyFilters"
      />
    </div>

    <DataTable
      :value="store.credentials"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="credential_type"
        header="Type"
      />
      <Column
        field="credential_name"
        header="Name"
      />
      <Column
        field="source_type"
        header="Source"
      />
      <Column
        field="source_location"
        header="Location"
      >
        <template #body="{ data }">
          <span class="location-text">{{ truncate(data.source_location, 50) }}</span>
        </template>
      </Column>
      <Column
        field="cloud_provider"
        header="Provider"
      />
      <Column
        field="is_active"
        header="Active"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.is_active ? 'danger' : 'success'"
            :value="data.is_active ? 'Yes' : 'No'"
          />
        </template>
      </Column>
      <Column
        field="remediation_status"
        header="Status"
      >
        <template #body="{ data }">
          <Tag
            :severity="getStatusSeverity(data.remediation_status)"
            :value="data.remediation_status"
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
import { ref, onMounted } from 'vue'
import { useExposedCredentialsStore } from '../stores/exposedCredentials'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Dropdown from 'primevue/dropdown'
import Paginator from 'primevue/paginator'

const store = useExposedCredentialsStore()

const filters = ref({
  credentialType: null,
  sourceType: null,
})

const credentialTypes = ['aws_access_key', 'api_key', 'password', 'token', 'certificate', 'ssh_key']
const sourceTypes = ['env_var', 'config_file', 'ssm_parameter', 'secrets_manager', 'lambda_env']

function truncate(str, len) {
  if (!str) return ''
  return str.length > len ? str.slice(0, len) + '...' : str
}

function getStatusSeverity(status) {
  const map = { pending: 'warning', in_progress: 'info', resolved: 'success', accepted: 'secondary' }
  return map[status] || 'secondary'
}

function applyFilters() {
  store.setFilters(filters.value)
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  store.fetchCredentials()
}

onMounted(() => {
  store.fetchCredentials()
  store.fetchSummary()
})
</script>

<style scoped>
.exposed-credentials-view { padding: 1.5rem; }
.page-header { margin-bottom: 1.5rem; }
.page-header h1 { margin: 0; font-size: 1.75rem; }
.subtitle { color: var(--text-color-secondary); margin-top: 0.25rem; }
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
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
.filter-dropdown { min-width: 150px; }
.location-text { font-family: monospace; font-size: 0.85rem; }
</style>
