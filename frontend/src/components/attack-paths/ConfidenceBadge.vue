<template>
  <div
    class="confidence-badge"
    :class="confidenceLevel"
    v-tooltip.top="tooltipContent"
  >
    <span class="confidence-value">{{ score }}%</span>
    <span class="confidence-label">confidence</span>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  score: {
    type: Number,
    required: true,
  },
  factors: {
    type: Object,
    default: () => ({}),
  },
})

// Computed
const confidenceLevel = computed(() => {
  if (props.score >= 80) return 'high'
  if (props.score >= 50) return 'medium'
  return 'low'
})

const tooltipContent = computed(() => {
  if (!props.factors || Object.keys(props.factors).length === 0) {
    return `Confidence: ${props.score}%`
  }

  const lines = ['Confidence Breakdown:']

  if (props.factors.tool_agreement) {
    lines.push(`• Tool Agreement: ${props.factors.tool_agreement.score}% (${props.factors.tool_agreement.details})`)
  }
  if (props.factors.poc_validation) {
    lines.push(`• PoC Validation: ${props.factors.poc_validation.score}% (${props.factors.poc_validation.details})`)
  }
  if (props.factors.evidence_count) {
    lines.push(`• Evidence Count: ${props.factors.evidence_count.score}% (${props.factors.evidence_count.details})`)
  }

  return lines.join('\n')
})
</script>

<style scoped>
.confidence-badge {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  padding: 0.375rem 0.625rem;
  border-radius: 6px;
  cursor: help;
}

.confidence-badge.high {
  background: var(--green-100);
  color: var(--green-700);
}

.confidence-badge.medium {
  background: var(--yellow-100);
  color: var(--yellow-700);
}

.confidence-badge.low {
  background: var(--red-100);
  color: var(--red-700);
}

.confidence-value {
  font-size: 1rem;
  font-weight: 700;
}

.confidence-label {
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
</style>
