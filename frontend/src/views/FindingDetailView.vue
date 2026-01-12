<template>
  <div class="finding-detail-view">
    <div class="detail-header">
      <Button
        icon="pi pi-arrow-left"
        label="Back to Findings"
        text
        @click="$router.push('/findings')"
      />
    </div>

    <div
      v-if="findingsStore.loading"
      class="loading"
    >
      <ProgressSpinner />
      <span>Loading finding details...</span>
    </div>

    <div
      v-else-if="findingsStore.error"
      class="error"
    >
      <i class="pi pi-exclamation-triangle" />
      {{ findingsStore.error }}
    </div>

    <div
      v-else-if="finding"
      class="detail-content"
    >
      <div class="finding-header-card card">
        <div class="finding-meta">
          <span
            class="severity-badge"
            :class="finding.severity"
          >
            {{ finding.severity }}
          </span>
          <span
            class="status-badge"
            :class="finding.status"
          >
            {{ finding.status }}
          </span>
          <span class="tool-badge">{{ finding.tool }}</span>
        </div>
        <h1>{{ finding.title }}</h1>
        <p class="finding-id">
          {{ finding.finding_id }}
        </p>
      </div>

      <div class="card">
        <FindingDetail :finding="finding" />
      </div>
    </div>

    <div
      v-else
      class="not-found"
    >
      <i class="pi pi-search" />
      <h2>Finding Not Found</h2>
      <p>The requested finding could not be found.</p>
      <Button
        label="Go to Findings"
        @click="$router.push('/findings')"
      />
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useFindingsStore } from '../stores/findings'
import FindingDetail from '../components/findings/FindingDetail.vue'

const route = useRoute()
const findingsStore = useFindingsStore()

const finding = computed(() => findingsStore.currentFinding)

onMounted(() => {
  const id = route.params.id
  if (id) {
    findingsStore.fetchFinding(id)
  }
})
</script>

<style scoped>
.finding-detail-view {
  max-width: 1000px;
  margin: 0 auto;
}

.detail-header {
  margin-bottom: var(--spacing-lg);
}

.detail-header :deep(.p-button) {
  color: white;
}

.detail-header :deep(.p-button:hover) {
  background: rgba(255, 255, 255, 0.1);
}

.loading,
.not-found {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl) * 2;
  color: white;
  gap: var(--spacing-md);
}

.not-found i {
  font-size: 4rem;
  opacity: 0.5;
}

.not-found h2 {
  margin: 0;
}

.error {
  background: rgba(231, 76, 60, 0.2);
  color: white;
  padding: var(--spacing-lg);
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.detail-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.finding-header-card {
  background: var(--bg-secondary);
}

.finding-meta {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.finding-header-card h1 {
  font-size: 1.5rem;
  margin: 0 0 var(--spacing-sm) 0;
  color: var(--text-primary);
}

.finding-id {
  font-family: 'Consolas', monospace;
  font-size: 0.75rem;
  color: var(--text-secondary);
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
</style>
