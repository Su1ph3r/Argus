<template>
  <Dialog
    v-model:visible="visible"
    modal
    :closable="!loading"
    :close-on-escape="!loading"
    header="Accept Risk"
    :style="{ width: '500px' }"
    class="accept-risk-modal"
  >
    <div class="modal-content">
      <div class="finding-summary">
        <h4>Finding</h4>
        <p class="finding-title">{{ finding?.title }}</p>
        <div class="finding-meta">
          <span class="severity-badge" :class="finding?.severity">
            {{ finding?.severity }}
          </span>
          <span class="resource">{{ finding?.resource_name || finding?.resource_id }}</span>
        </div>
      </div>

      <div class="form-group">
        <label for="justification">Justification (required)</label>
        <Textarea
          id="justification"
          v-model="justification"
          :disabled="loading"
          placeholder="Explain why this risk is being accepted (minimum 20 characters)"
          rows="4"
          :class="{ 'p-invalid': justificationError }"
        />
        <small v-if="justificationError" class="p-error">
          {{ justificationError }}
        </small>
        <small class="char-count" :class="{ warning: justification.length < 20 }">
          {{ justification.length }}/20 minimum characters
        </small>
      </div>

      <div class="form-group">
        <label for="expiration">Expiration Date (optional)</label>
        <Calendar
          id="expiration"
          v-model="expirationDate"
          :disabled="loading"
          :min-date="minDate"
          date-format="yy-mm-dd"
          placeholder="Leave empty for permanent exception"
          show-icon
          show-button-bar
        />
        <small class="hint">
          Leave empty for a permanent exception, or set a date for automatic re-evaluation
        </small>
      </div>

      <div v-if="error" class="error-message">
        <i class="pi pi-exclamation-triangle" />
        {{ error }}
      </div>
    </div>

    <template #footer>
      <Button
        label="Cancel"
        severity="secondary"
        :disabled="loading"
        @click="close"
      />
      <Button
        label="Accept Risk"
        severity="warning"
        :loading="loading"
        :disabled="!isValid"
        @click="submit"
      />
    </template>
  </Dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRiskExceptionsStore } from '../../stores/riskExceptions'

const props = defineProps({
  finding: {
    type: Object,
    default: null,
  },
  modelValue: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['update:modelValue', 'accepted'])

const riskExceptionsStore = useRiskExceptionsStore()

// State
const justification = ref('')
const expirationDate = ref(null)
const loading = ref(false)
const error = ref(null)

// Computed
const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

const minDate = computed(() => {
  const date = new Date()
  date.setDate(date.getDate() + 1) // At least 1 day in the future
  return date
})

const justificationError = computed(() => {
  if (justification.value.length > 0 && justification.value.length < 20) {
    return 'Justification must be at least 20 characters'
  }
  return null
})

const isValid = computed(() => {
  return justification.value.length >= 20
})

// Reset form when modal opens
watch(visible, (newValue) => {
  if (newValue) {
    justification.value = ''
    expirationDate.value = null
    error.value = null
  }
})

// Methods
function close() {
  visible.value = false
}

async function submit() {
  if (!isValid.value || !props.finding) return

  loading.value = true
  error.value = null

  try {
    const formattedDate = expirationDate.value
      ? expirationDate.value.toISOString()
      : null

    const exception = await riskExceptionsStore.createException(
      [props.finding.id],
      justification.value,
      formattedDate
    )

    emit('accepted', exception)
    close()
  } catch (err) {
    error.value = err.message || 'Failed to accept risk'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.accept-risk-modal .modal-content {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.finding-summary {
  background: var(--surface-100);
  border-radius: 8px;
  padding: 1rem;
}

.finding-summary h4 {
  margin: 0 0 0.5rem 0;
  font-size: 0.875rem;
  color: var(--text-color-secondary);
  text-transform: uppercase;
}

.finding-title {
  margin: 0 0 0.5rem 0;
  font-weight: 600;
}

.finding-meta {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.severity-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.severity-badge.critical { background: #fee2e2; color: #991b1b; }
.severity-badge.high { background: #ffedd5; color: #9a3412; }
.severity-badge.medium { background: #fef3c7; color: #92400e; }
.severity-badge.low { background: #dbeafe; color: #1e40af; }
.severity-badge.info { background: #e0e7ff; color: #3730a3; }

.resource {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
}

.char-count {
  text-align: right;
  color: var(--text-color-secondary);
}

.char-count.warning {
  color: var(--yellow-500);
}

.hint {
  color: var(--text-color-secondary);
}

.error-message {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: #fee2e2;
  color: #991b1b;
  border-radius: 6px;
}
</style>
