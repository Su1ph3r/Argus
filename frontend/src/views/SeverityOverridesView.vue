<template>
  <div class="severity-overrides-view">
    <div class="page-header">
      <div class="header-content">
        <h1>Severity Overrides</h1>
        <p class="subtitle">
          Custom severity adjustments for findings
        </p>
      </div>
    </div>

    <div class="filters-section">
      <Dropdown
        v-model="filters.approvalStatus"
        :options="statusOptions"
        placeholder="Approval Status"
        class="filter-dropdown"
        @change="applyFilters"
      />
    </div>

    <DataTable
      :value="store.overrides"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="finding_id"
        header="Finding ID"
      />
      <Column
        field="original_severity"
        header="Original"
      >
        <template #body="{ data }">
          <Tag
            :severity="getSeverity(data.original_severity)"
            :value="data.original_severity"
          />
        </template>
      </Column>
      <Column
        field="new_severity"
        header="New"
      >
        <template #body="{ data }">
          <Tag
            :severity="getSeverity(data.new_severity)"
            :value="data.new_severity"
          />
        </template>
      </Column>
      <Column
        field="justification"
        header="Justification"
      >
        <template #body="{ data }">
          <span>{{ truncate(data.justification, 60) }}</span>
        </template>
      </Column>
      <Column
        field="approval_status"
        header="Status"
      >
        <template #body="{ data }">
          <Tag
            :severity="getApprovalSeverity(data.approval_status)"
            :value="data.approval_status"
          />
        </template>
      </Column>
      <Column
        field="created_by"
        header="Created By"
      />
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            v-if="data.approval_status === 'pending'"
            icon="pi pi-check"
            class="p-button-success p-button-text"
            @click="approveOverride(data.id)"
          />
          <Button
            v-if="data.approval_status === 'pending'"
            icon="pi pi-times"
            class="p-button-danger p-button-text"
            @click="rejectOverride(data.id)"
          />
          <Button
            icon="pi pi-trash"
            class="p-button-text"
            @click="deleteOverride(data.id)"
          />
        </template>
      </Column>
    </DataTable>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useSeverityOverridesStore } from '../stores/severityOverrides'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'

const store = useSeverityOverridesStore()

const filters = ref({ approvalStatus: null })
const statusOptions = ['pending', 'approved', 'rejected']

function truncate(str, len) {
  if (!str) return ''
  return str.length > len ? str.slice(0, len) + '...' : str
}

function getSeverity(level) {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success', info: 'secondary' }
  return map[level] || 'secondary'
}

function getApprovalSeverity(status) {
  const map = { pending: 'warning', approved: 'success', rejected: 'danger' }
  return map[status] || 'secondary'
}

function applyFilters() {
  store.filters.approvalStatus = filters.value.approvalStatus
  store.fetchOverrides()
}

async function approveOverride(id) {
  await store.approveOverride(id, true, 'Admin', null)
}

async function rejectOverride(id) {
  await store.approveOverride(id, false, 'Admin', null)
}

async function deleteOverride(id) {
  await store.deleteOverride(id)
}

onMounted(() => {
  store.fetchOverrides()
})
</script>

<style scoped>
.severity-overrides-view { padding: 1.5rem; }
.page-header { margin-bottom: 1.5rem; }
.page-header h1 { margin: 0; font-size: 1.75rem; }
.subtitle { color: var(--text-color-secondary); margin-top: 0.25rem; }
.filters-section { display: flex; gap: 1rem; margin-bottom: 1rem; }
.filter-dropdown { min-width: 150px; }
</style>
