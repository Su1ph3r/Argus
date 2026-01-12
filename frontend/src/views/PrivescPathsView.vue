<template>
  <div class="privesc-paths-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Privilege Escalation Paths</h1>
        <p class="subtitle">
          IAM misconfigurations enabling privilege escalation
        </p>
      </div>
    </div>

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card critical">
        <div class="card-value">
          {{ store.summary.critical_paths }}
        </div>
        <div class="card-label">
          Critical
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.high_risk_paths }}
        </div>
        <div class="card-label">
          High Risk
        </div>
      </div>
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_paths }}
        </div>
        <div class="card-label">
          Total
        </div>
      </div>
    </div>

    <DataTable
      :value="store.paths"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="escalation_method"
        header="Method"
      />
      <Column
        field="source_principal_name"
        header="Source"
      />
      <Column
        field="target_principal_name"
        header="Target"
      />
      <Column
        field="cloud_provider"
        header="Provider"
      />
      <Column
        field="risk_score"
        header="Risk Score"
      >
        <template #body="{ data }">
          <ProgressBar
            :value="data.risk_score"
            :show-value="true"
            class="risk-bar"
          />
        </template>
      </Column>
      <Column
        field="exploitability"
        header="Exploitability"
      >
        <template #body="{ data }">
          <Tag
            :severity="getExploitSeverity(data.exploitability)"
            :value="data.exploitability"
          />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            icon="pi pi-eye"
            text
            @click="viewPath(data)"
          />
          <Button
            icon="pi pi-download"
            text
            @click="exportPath(data.id)"
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
import { onMounted } from 'vue'
import { usePrivescPathsStore } from '../stores/privescPaths'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import ProgressBar from 'primevue/progressbar'
import Paginator from 'primevue/paginator'

const store = usePrivescPathsStore()

function getExploitSeverity(level) {
  const map = { confirmed: 'danger', likely: 'warning', theoretical: 'info' }
  return map[level] || 'secondary'
}

function viewPath(path) {
  console.log('View path:', path)
}

async function exportPath(id) {
  const result = await store.exportPath(id, 'markdown')
  console.log('Export:', result)
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  store.fetchPaths()
}

onMounted(() => {
  store.fetchPaths()
  store.fetchSummary()
})
</script>

<style scoped>
.privesc-paths-view { padding: 1.5rem; }
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
.summary-card.info { border-left-color: var(--blue-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.risk-bar { height: 8px; }
</style>
