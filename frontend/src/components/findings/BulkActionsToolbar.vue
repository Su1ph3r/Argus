<template>
  <div v-if="selectedCount > 0" class="bulk-actions-toolbar">
    <div class="selection-info">
      <Checkbox
        :model-value="allSelected"
        :indeterminate="someSelected && !allSelected"
        binary
        @change="toggleSelectAll"
      />
      <span class="selection-count">
        {{ selectedCount }} finding{{ selectedCount !== 1 ? 's' : '' }} selected
      </span>
      <Button
        label="Clear"
        severity="secondary"
        text
        size="small"
        @click="clearSelection"
      />
    </div>

    <div class="actions">
      <Dropdown
        v-model="selectedStatus"
        :options="statusOptions"
        option-label="label"
        option-value="value"
        placeholder="Change Status"
        :disabled="loading"
        class="status-dropdown"
      />
      <Button
        label="Apply"
        :disabled="!selectedStatus || loading"
        :loading="loading"
        size="small"
        @click="applyStatusChange"
      />

      <Divider layout="vertical" />

      <Button
        label="Accept Risk"
        severity="warning"
        :disabled="loading"
        size="small"
        @click="$emit('accept-risk')"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { toast } from '../../services/toast'

const props = defineProps({
  selectedIds: {
    type: Array,
    default: () => [],
  },
  totalCount: {
    type: Number,
    default: 0,
  },
})

const emit = defineEmits(['selection-change', 'accept-risk', 'status-changed'])

// State
const selectedStatus = ref(null)
const loading = ref(false)

const statusOptions = [
  { label: 'Open', value: 'open' },
  { label: 'Closed', value: 'closed' },
  { label: 'Mitigated', value: 'mitigated' },
]

// Computed
const selectedCount = computed(() => props.selectedIds.length)

const allSelected = computed(() => {
  return props.selectedIds.length > 0 && props.selectedIds.length === props.totalCount
})

const someSelected = computed(() => {
  return props.selectedIds.length > 0 && props.selectedIds.length < props.totalCount
})

// Methods
function toggleSelectAll() {
  if (allSelected.value) {
    emit('selection-change', [])
  } else {
    emit('selection-change', 'all')
  }
}

function clearSelection() {
  emit('selection-change', [])
}

async function applyStatusChange() {
  if (!selectedStatus.value || props.selectedIds.length === 0) return

  loading.value = true

  try {
    const response = await fetch('/api/findings/bulk', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        finding_ids: props.selectedIds,
        action: 'update_status',
        status: selectedStatus.value,
      }),
    })

    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.detail || 'Failed to update findings')
    }

    const result = await response.json()

    toast.success(
      'Status Updated',
      `Updated ${result.updated} finding${result.updated !== 1 ? 's' : ''}`
    )

    if (result.failed > 0) {
      toast.warning(
        'Some Updates Failed',
        `${result.failed} finding${result.failed !== 1 ? 's' : ''} could not be updated`
      )
    }

    emit('status-changed', result)
    selectedStatus.value = null
  } catch (err) {
    toast.apiError(err, 'Failed to update findings')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.bulk-actions-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1rem;
  background: var(--surface-100);
  border-radius: 8px;
  margin-bottom: 1rem;
}

.selection-info {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.selection-count {
  font-weight: 500;
}

.actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.status-dropdown {
  width: 150px;
}
</style>
