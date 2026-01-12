<template>
  <div class="findings-table-container">
    <DataTable
      v-model:expanded-rows="expandedRows"
      :value="findings"
      :loading="loading"
      :rows="pageSize"
      :total-records="total"
      :lazy="true"
      :sort-field="sortField"
      :sort-order="sortOrder"
      data-key="id"
      scrollable
      scroll-height="flex"
      striped-rows
      show-gridlines
      class="findings-table"
      @page="onPage"
      @sort="onSort"
    >
      <template #empty>
        <div class="empty-state">
          <i class="pi pi-inbox" />
          <p>No findings found</p>
          <span v-if="hasFilters">Try adjusting your filters</span>
        </div>
      </template>

      <template #loading>
        <div class="loading-state">
          <ProgressSpinner />
          <span>Loading findings...</span>
        </div>
      </template>

      <!-- Expander Column -->
      <Column
        expander
        style="width: 3rem"
      />

      <!-- Severity -->
      <Column
        field="severity"
        header="Severity"
        :sortable="true"
        style="width: 100px"
      >
        <template #body="{ data }">
          <span
            class="severity-badge"
            :class="data.severity"
          >
            {{ data.severity }}
          </span>
        </template>
      </Column>

      <!-- Tool -->
      <Column
        field="tool"
        header="Tool"
        :sortable="true"
        style="width: 120px"
      >
        <template #body="{ data }">
          <span class="tool-badge">{{ data.tool }}</span>
        </template>
      </Column>

      <!-- Title -->
      <Column
        field="title"
        header="Finding"
        :sortable="true"
        style="min-width: 300px"
      >
        <template #body="{ data }">
          <div class="finding-title-cell">
            <span class="title">{{ data.title }}</span>
            <span
              v-if="data.resource_name"
              class="resource-name"
            >
              {{ data.resource_name }}
            </span>
          </div>
        </template>
      </Column>

      <!-- Resource Type -->
      <Column
        field="resource_type"
        header="Resource Type"
        :sortable="true"
        style="width: 150px"
      />

      <!-- Region -->
      <Column
        field="region"
        header="Region"
        :sortable="true"
        style="width: 120px"
      />

      <!-- Status -->
      <Column
        field="status"
        header="Status"
        :sortable="true"
        style="width: 100px"
      >
        <template #body="{ data }">
          <span
            class="status-badge"
            :class="data.status"
          >
            {{ data.status }}
          </span>
        </template>
      </Column>

      <!-- Scan Date -->
      <Column
        field="scan_date"
        header="Date"
        :sortable="true"
        style="width: 150px"
      >
        <template #body="{ data }">
          {{ formatDate(data.scan_date) }}
        </template>
      </Column>

      <!-- Row Expansion Template -->
      <template #expansion="{ data }">
        <FindingDetail :finding="data" />
      </template>
    </DataTable>

    <!-- Pagination -->
    <div class="pagination-container">
      <div class="pagination-info">
        Showing {{ startItem }} to {{ endItem }} of {{ total }} findings
      </div>
      <Paginator
        :rows="pageSize"
        :total-records="total"
        :first="(page - 1) * pageSize"
        :rows-per-page-options="[25, 50, 100]"
        @page="onPageChange"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import FindingDetail from './FindingDetail.vue'

const props = defineProps({
  findings: {
    type: Array,
    default: () => [],
  },
  total: {
    type: Number,
    default: 0,
  },
  page: {
    type: Number,
    default: 1,
  },
  pageSize: {
    type: Number,
    default: 50,
  },
  loading: {
    type: Boolean,
    default: false,
  },
  hasFilters: {
    type: Boolean,
    default: false,
  },
  sortField: {
    type: String,
    default: 'risk_score',
  },
  sortOrder: {
    type: Number,
    default: -1,  // -1 for descending, 1 for ascending
  },
})

const emit = defineEmits(['page-change', 'sort-change'])

const expandedRows = ref([])

const startItem = computed(() => {
  if (props.total === 0) return 0
  return (props.page - 1) * props.pageSize + 1
})

const endItem = computed(() => {
  const end = props.page * props.pageSize
  return end > props.total ? props.total : end
})

const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A'
  return new Date(dateStr).toLocaleDateString()
}

const onPage = (event) => {
  emit('page-change', {
    page: event.page + 1,
    pageSize: event.rows,
  })
}

const onPageChange = (event) => {
  emit('page-change', {
    page: event.page + 1,
    pageSize: event.rows,
  })
}

const onSort = (event) => {
  emit('sort-change', {
    field: event.sortField,
    order: event.sortOrder,
  })
}
</script>

<style scoped>
.findings-table-container {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.findings-table {
  flex: 1;
}

:deep(.p-datatable) {
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  overflow: hidden;
}

:deep(.p-datatable-thead > tr > th) {
  background: var(--header-bg);
  color: white;
  font-weight: 600;
  font-size: 0.8125rem;
  text-transform: uppercase;
  padding: var(--spacing-md);
}

:deep(.p-datatable-tbody > tr > td) {
  padding: var(--spacing-md);
  font-size: 0.875rem;
}

:deep(.p-datatable-tbody > tr.p-datatable-row-expansion > td) {
  padding: 0;
}

.finding-title-cell {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.finding-title-cell .title {
  font-weight: 500;
}

.finding-title-cell .resource-name {
  font-size: 0.75rem;
  color: var(--text-secondary);
  font-family: 'Consolas', monospace;
}

.tool-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  background: rgba(102, 126, 234, 0.1);
  color: var(--gradient-start);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 500;
}

.empty-state,
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  color: var(--text-secondary);
  gap: var(--spacing-md);
}

.empty-state i {
  font-size: 3rem;
  opacity: 0.5;
}

.pagination-container {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md);
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-color);
}

.pagination-info {
  font-size: 0.875rem;
  color: var(--text-secondary);
}

@media (max-width: 768px) {
  .pagination-container {
    flex-direction: column;
    gap: var(--spacing-md);
  }
}
</style>
