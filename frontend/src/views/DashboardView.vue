<template>
  <div class="dashboard">
    <div class="dashboard-header">
      <div class="header-content">
        <h2>Security Dashboard</h2>
        <p class="subtitle">
          Overview of security findings across all tools and environments
        </p>
      </div>
      <div
        v-if="!summaryStore.loading"
        class="header-badge"
      >
        <span class="badge-value">{{ summaryStore.totalFindings }}</span>
        <span class="badge-label">Total Findings</span>
      </div>
    </div>

    <div
      v-if="summaryStore.loading"
      class="loading-container"
    >
      <ProgressSpinner />
      <span>Loading dashboard data...</span>
    </div>

    <div
      v-else-if="summaryStore.error"
      class="error-container"
    >
      <i class="pi pi-exclamation-triangle" />
      <span>{{ summaryStore.error }}</span>
    </div>

    <template v-else>
      <!-- Severity Cards -->
      <section class="section">
        <SeverityCards @filter="handleSeverityFilter" />
      </section>

      <!-- Charts Row -->
      <section class="section">
        <div class="charts-grid">
          <div class="chart-card">
            <div class="chart-header">
              <h3>Findings by Severity</h3>
            </div>
            <SeverityChart
              :data="summaryStore.severityData"
            />
          </div>
          <div class="chart-card">
            <div class="chart-header">
              <h3>Findings by Tool</h3>
            </div>
            <SeverityChart
              :data="toolChartData"
            />
          </div>
          <div class="chart-card">
            <div class="chart-header">
              <h3>Findings by Provider</h3>
            </div>
            <SeverityChart
              :data="providerChartData"
            />
          </div>
        </div>
      </section>

      <!-- Quick Stats -->
      <section class="section">
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-icon">
              <i class="pi pi-shield" />
            </div>
            <div class="stat-content">
              <div class="stat-value">
                {{ summaryStore.totalFindings }}
              </div>
              <div class="stat-label">
                Total Open Findings
              </div>
            </div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">
              <i class="pi pi-cog" />
            </div>
            <div class="stat-content">
              <div class="stat-value">
                {{ toolCount }}
              </div>
              <div class="stat-label">
                Security Tools
              </div>
            </div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">
              <i class="pi pi-cloud" />
            </div>
            <div class="stat-content">
              <div class="stat-value">
                {{ providerCount }}
              </div>
              <div class="stat-label">
                Cloud Providers
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Risk Trend Chart (Phase 1 Feature) -->
      <section class="section">
        <RiskTrendChart />
      </section>

      <!-- Health & Compliance Grid (Phase 1 Feature) -->
      <section class="section">
        <div class="health-compliance-grid">
          <ToolHealthCard />
          <ComplianceOverview />
        </div>
      </section>

      <!-- Action Buttons -->
      <section class="section actions-section">
        <Button
          label="View All Findings"
          icon="pi pi-list"
          class="action-btn primary"
          @click="$router.push('/findings')"
        />
        <Button
          label="Export Report"
          icon="pi pi-download"
          severity="secondary"
          class="action-btn"
          @click="exportReport"
        />
        <a
          href="/reports/"
          target="_blank"
          rel="noopener"
          class="action-btn link-btn"
        >
          <i class="pi pi-folder" />
          <span>Browse Raw Reports</span>
        </a>
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useSummaryStore } from '../stores/summary'
import { useFindingsStore } from '../stores/findings'
import SeverityCards from '../components/dashboard/SeverityCards.vue'
import SeverityChart from '../components/dashboard/SeverityChart.vue'
import RiskTrendChart from '../components/dashboard/RiskTrendChart.vue'
import ToolHealthCard from '../components/dashboard/ToolHealthCard.vue'
import ComplianceOverview from '../components/dashboard/ComplianceOverview.vue'

const router = useRouter()
const summaryStore = useSummaryStore()
const findingsStore = useFindingsStore()

let refreshInterval = null

// Generate colors for tool/provider charts
const toolColors = ['#3b82f6', '#2563eb', '#ec4899', '#f43f5e', '#ea580c', '#ca8a04', '#0891b2', '#14b8a6']
const providerColors = ['#3b82f6', '#2563eb', '#1d4ed8', '#0891b2', '#d946ef', '#ec4899']

const toolChartData = computed(() =>
  summaryStore.byTool.map((item, index) => ({
    ...item,
    color: toolColors[index % toolColors.length],
  })),
)

const providerChartData = computed(() =>
  summaryStore.byProvider.map((item, index) => ({
    ...item,
    color: providerColors[index % providerColors.length],
  })),
)

const toolCount = computed(() => summaryStore.byTool.length)
const providerCount = computed(() => summaryStore.byProvider.length)

const handleSeverityFilter = (severity) => {
  findingsStore.setFilter('severity', severity)
  router.push('/findings')
}

const exportReport = () => {
  window.open('/api/exports/csv?include_remediation=true', '_blank')
}

onMounted(() => {
  refreshInterval = summaryStore.startAutoRefresh(30000)
})

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
  }
})
</script>

<style scoped>
.dashboard {
  max-width: 1400px;
  margin: 0 auto;
}

.dashboard-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: var(--spacing-xl);
  gap: var(--spacing-lg);
}

.header-content h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: var(--spacing-xs);
}

.header-content .subtitle {
  color: var(--text-secondary);
  font-size: 0.9375rem;
}

.header-badge {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  padding: var(--spacing-md) var(--spacing-lg);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
}

.header-badge .badge-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--accent-primary);
  line-height: 1;
}

.header-badge .badge-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.03em;
  margin-top: var(--spacing-xs);
}

.section {
  margin-bottom: var(--spacing-xl);
}

.charts-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--spacing-lg);
}

@media (max-width: 1200px) {
  .charts-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .charts-grid {
    grid-template-columns: 1fr;
  }
}

.chart-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
  transition: all var(--transition-normal);
}

.chart-card:hover {
  border-color: var(--border-color-light);
  box-shadow: var(--shadow-md);
}

.chart-header {
  margin-bottom: var(--spacing-md);
}

.chart-header h3 {
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--text-primary);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--spacing-md);
}

@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }
}

.stat-card {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
  transition: all var(--transition-normal);
}

.stat-card:hover {
  border-color: var(--border-color-light);
  box-shadow: var(--shadow-md);
}

.stat-icon {
  width: 48px;
  height: 48px;
  border-radius: var(--radius-md);
  background: var(--accent-primary-bg);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--accent-primary);
  font-size: 1.25rem;
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1;
}

.stat-label {
  font-size: 0.8125rem;
  color: var(--text-secondary);
  margin-top: var(--spacing-xs);
}

.actions-section {
  display: flex;
  gap: var(--spacing-md);
  flex-wrap: wrap;
}

.action-btn {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--radius-md);
  font-weight: 500;
  font-size: 0.875rem;
  transition: all var(--transition-fast);
}

.action-btn.primary {
  background: var(--accent-primary) !important;
  border-color: var(--accent-primary) !important;
}

.action-btn.primary:hover {
  background: var(--accent-primary-hover) !important;
  transform: translateY(-1px);
}

.link-btn {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  text-decoration: none;
  cursor: pointer;
}

.link-btn:hover {
  background: var(--bg-card-hover);
  border-color: var(--border-color-light);
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl) * 2;
  color: var(--text-secondary);
  gap: var(--spacing-md);
}

.error-container {
  background: var(--severity-critical-bg);
  border: 1px solid var(--severity-critical-border);
  color: var(--severity-critical);
  padding: var(--spacing-lg);
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  font-weight: 500;
}

/* Health & Compliance Grid (Phase 1 Feature) */
.health-compliance-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: var(--spacing-lg);
}

@media (max-width: 1024px) {
  .health-compliance-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .dashboard-header {
    flex-direction: column;
  }

  .header-badge {
    align-items: flex-start;
  }
}
</style>
