<template>
  <div class="severity-cards">
    <div
      v-for="card in cards"
      :key="card.severity"
      class="severity-card"
      :class="card.severity"
      @click="$emit('filter', card.severity)"
    >
      <div class="card-header">
        <div
          class="card-icon"
          :style="{ background: card.bgColor }"
        >
          <i
            :class="card.icon"
            :style="{ color: card.color }"
          />
        </div>
        <div
          v-if="card.value > 0"
          class="card-trend"
        >
          <i class="pi pi-arrow-right" />
        </div>
      </div>
      <div class="card-content">
        <div
          class="card-value"
          :style="{ color: card.color }"
        >
          {{ card.value }}
        </div>
        <div class="card-label">
          {{ card.label }}
        </div>
      </div>
      <div
        class="card-glow"
        :style="{ background: card.glowColor }"
      />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useSummaryStore } from '../../stores/summary'

const emit = defineEmits(['filter'])
const summaryStore = useSummaryStore()

const cards = computed(() => [
  {
    severity: 'critical',
    label: 'Critical',
    value: summaryStore.criticalCount,
    icon: 'pi pi-exclamation-triangle',
    color: 'var(--severity-critical)',
    bgColor: 'var(--severity-critical-bg)',
    glowColor: 'rgba(239, 68, 68, 0.15)',
  },
  {
    severity: 'high',
    label: 'High',
    value: summaryStore.highCount,
    icon: 'pi pi-exclamation-circle',
    color: 'var(--severity-high)',
    bgColor: 'var(--severity-high-bg)',
    glowColor: 'rgba(249, 115, 22, 0.15)',
  },
  {
    severity: 'medium',
    label: 'Medium',
    value: summaryStore.mediumCount,
    icon: 'pi pi-info-circle',
    color: 'var(--severity-medium)',
    bgColor: 'var(--severity-medium-bg)',
    glowColor: 'rgba(234, 179, 8, 0.15)',
  },
  {
    severity: 'low',
    label: 'Low',
    value: summaryStore.lowCount,
    icon: 'pi pi-check-circle',
    color: 'var(--severity-low)',
    bgColor: 'var(--severity-low-bg)',
    glowColor: 'rgba(34, 197, 94, 0.15)',
  },
])
</script>

<style scoped>
.severity-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
}

@media (max-width: 1200px) {
  .severity-cards {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 600px) {
  .severity-cards {
    grid-template-columns: 1fr;
  }
}

.severity-card {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: all var(--transition-normal);
  overflow: hidden;
}

.severity-card:hover {
  transform: translateY(-4px);
  box-shadow: var(--shadow-lg);
  border-color: var(--border-color-light);
}

.severity-card:hover .card-glow {
  opacity: 1;
}

.severity-card:hover .card-trend {
  opacity: 1;
  transform: translateX(4px);
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.card-icon {
  width: 48px;
  height: 48px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
}

.card-trend {
  opacity: 0;
  color: var(--text-tertiary);
  transition: all var(--transition-fast);
}

.card-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.card-value {
  font-size: 2.5rem;
  font-weight: 700;
  line-height: 1;
  letter-spacing: -0.02em;
}

.card-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.card-glow {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 50%;
  opacity: 0;
  transition: opacity var(--transition-normal);
  pointer-events: none;
  filter: blur(30px);
}
</style>
