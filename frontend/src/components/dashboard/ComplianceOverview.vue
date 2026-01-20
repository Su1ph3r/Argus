<template>
  <div class="compliance-container">
    <div class="compliance-header">
      <h3>Compliance Overview</h3>
      <router-link
        to="/compliance"
        class="view-all"
      >
        View All <i class="pi pi-arrow-right" />
      </router-link>
    </div>

    <div
      v-if="loading"
      class="loading-state"
    >
      <i class="pi pi-spin pi-spinner" />
      <span>Loading compliance data...</span>
    </div>

    <div
      v-else-if="error"
      class="error-state"
    >
      <i class="pi pi-exclamation-circle" />
      <span>{{ error }}</span>
    </div>

    <div
      v-else-if="frameworks.length === 0"
      class="empty-state"
    >
      <i class="pi pi-check-circle" />
      <span>No compliance data available</span>
    </div>

    <div
      v-else
      class="frameworks-grid"
    >
      <div
        v-for="framework in topFrameworks"
        :key="framework.framework"
        class="framework-card"
        @click="navigateToFramework(framework.framework)"
      >
        <div class="framework-header">
          <span class="framework-name">{{ framework.framework }}</span>
          <span
            :class="['compliance-score', getScoreClass(framework.compliance_percentage)]"
          >
            {{ Math.round(framework.compliance_percentage) }}%
          </span>
        </div>
        <div class="progress-bar">
          <div
            class="progress-fill"
            :class="getScoreClass(framework.compliance_percentage)"
            :style="{ width: framework.compliance_percentage + '%' }"
          />
        </div>
        <div class="framework-stats">
          <span class="stat passed">
            <i class="pi pi-check" />
            {{ framework.passed_checks }}
          </span>
          <span class="stat failed">
            <i class="pi pi-times" />
            {{ framework.failed_checks }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../../services/api'

const router = useRouter()
const loading = ref(true)
const error = ref(null)
const frameworks = ref([])

const topFrameworks = computed(() => {
  return frameworks.value.slice(0, 6)
})

const fetchCompliance = async () => {
  loading.value = true
  error.value = null

  try {
    const response = await api.getComplianceSummary()
    frameworks.value = response.frameworks || []
  } catch (err) {
    error.value = 'Failed to load compliance data'
    console.error('Error fetching compliance:', err)
  } finally {
    loading.value = false
  }
}

const getScoreClass = (percentage) => {
  if (percentage >= 80) return 'good'
  if (percentage >= 60) return 'warning'
  return 'poor'
}

const navigateToFramework = (framework) => {
  router.push({ path: '/compliance', query: { framework } })
}

onMounted(() => {
  fetchCompliance()
})
</script>

<style scoped>
.compliance-container {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
}

.compliance-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.compliance-header h3 {
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
}

.view-all {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  font-size: 0.75rem;
  color: var(--accent-primary);
  text-decoration: none;
  transition: color 0.2s ease;
}

.view-all:hover {
  color: var(--accent-primary-hover);
}

.frameworks-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: var(--spacing-md);
}

.framework-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: var(--spacing-md);
  cursor: pointer;
  transition: all 0.2s ease;
}

.framework-card:hover {
  border-color: var(--accent-primary);
  transform: translateY(-2px);
}

.framework-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.framework-name {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-primary);
  line-height: 1.2;
  max-width: 70%;
}

.compliance-score {
  font-size: 0.8125rem;
  font-weight: 700;
}

.compliance-score.good {
  color: var(--severity-low);
}

.compliance-score.warning {
  color: var(--severity-medium);
}

.compliance-score.poor {
  color: var(--severity-critical);
}

.progress-bar {
  height: 4px;
  background: var(--bg-tertiary);
  border-radius: 2px;
  overflow: hidden;
  margin-bottom: var(--spacing-sm);
}

.progress-fill {
  height: 100%;
  border-radius: 2px;
  transition: width 0.3s ease;
}

.progress-fill.good {
  background: var(--severity-low);
}

.progress-fill.warning {
  background: var(--severity-medium);
}

.progress-fill.poor {
  background: var(--severity-critical);
}

.framework-stats {
  display: flex;
  gap: var(--spacing-md);
}

.stat {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  color: var(--text-muted);
}

.stat.passed i {
  color: var(--severity-low);
}

.stat.failed i {
  color: var(--severity-critical);
}

.loading-state,
.error-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-xl);
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.error-state {
  color: var(--severity-critical);
}
</style>
