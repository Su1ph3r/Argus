<template>
  <div class="assumed-roles-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Assumed Role Mapper</h1>
        <p class="subtitle">
          Role assumption relationships for visualization
        </p>
      </div>
      <div class="header-actions">
        <Button
          label="Analyze Roles"
          icon="pi pi-search"
          :loading="analyzing"
          style="margin-right: 0.5rem"
          @click="analyzeRoles"
        />
        <Button
          label="Sync to Neo4j"
          icon="pi pi-sync"
          :loading="store.loading"
          @click="syncAll"
        />
      </div>
    </div>

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_mappings }}
        </div>
        <div class="card-label">
          Total Mappings
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.cross_account }}
        </div>
        <div class="card-label">
          Cross-Account
        </div>
      </div>
      <div class="summary-card medium">
        <div class="card-value">
          {{ store.summary.external_id_required }}
        </div>
        <div class="card-label">
          External ID Required
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Button
        :label="showCrossAccountOnly ? 'Show All' : 'Show Cross-Account'"
        :icon="showCrossAccountOnly ? 'pi pi-list' : 'pi pi-share-alt'"
        @click="toggleCrossAccount"
      />
    </div>

    <DataTable
      :value="store.mappings"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="source_principal_name"
        header="Source"
      />
      <Column
        field="source_principal_type"
        header="Source Type"
      />
      <Column
        field="target_role_name"
        header="Target Role"
      />
      <Column
        field="target_account_id"
        header="Target Account"
      />
      <Column
        field="is_cross_account"
        header="Cross-Account"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.is_cross_account ? 'warning' : 'secondary'"
            :value="data.is_cross_account ? 'Yes' : 'No'"
          />
        </template>
      </Column>
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
        field="neo4j_synced"
        header="Synced"
      >
        <template #body="{ data }">
          <i :class="data.neo4j_synced ? 'pi pi-check text-success' : 'pi pi-times text-danger'" />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            icon="pi pi-code"
            text
            title="Get Cypher Query"
            @click="getCypher(data.id)"
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
import { useAssumedRolesStore } from '../stores/assumedRoles'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Paginator from 'primevue/paginator'

const store = useAssumedRolesStore()
const showCrossAccountOnly = ref(false)
const analyzing = ref(false)

function getRiskSeverity(level) {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[level] || 'secondary'
}

function toggleCrossAccount() {
  showCrossAccountOnly.value = !showCrossAccountOnly.value
  if (showCrossAccountOnly.value) {
    store.fetchCrossAccount()
  } else {
    store.fetchMappings()
  }
}

async function syncAll() {
  await store.syncToNeo4j(null, true)
}

async function analyzeRoles() {
  analyzing.value = true
  try {
    await store.analyzeRoles()
    // Refresh data after analysis
    await store.fetchMappings()
    await store.fetchSummary()
  } finally {
    analyzing.value = false
  }
}

async function getCypher(id) {
  const result = await store.getNeo4jQuery(id)
  // TODO: Display cypher query in a modal or copy to clipboard
  if (result?.cypher_query) {
    navigator.clipboard?.writeText(result.cypher_query)
  }
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  if (showCrossAccountOnly.value) {
    store.fetchCrossAccount()
  } else {
    store.fetchMappings()
  }
}

onMounted(() => {
  store.fetchMappings()
  store.fetchSummary()
})
</script>

<style scoped>
.assumed-roles-view { padding: 1.5rem; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }
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
.summary-card.info { border-left-color: var(--blue-500); }
.summary-card.high { border-left-color: var(--orange-500); }
.summary-card.medium { border-left-color: var(--yellow-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { margin-bottom: 1rem; }
.text-success { color: var(--green-500); }
.text-danger { color: var(--red-500); }
</style>
