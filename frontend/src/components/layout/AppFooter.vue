<template>
  <footer class="app-footer">
    <div class="footer-content">
      <div class="footer-left">
        <span
          class="api-status"
          :class="apiStatus"
        >
          <i :class="statusIcon" />
          API: {{ statusText }}
        </span>
      </div>
      <div class="footer-center">
        <span>Nubicustos - Cloud Security Audit Platform</span>
      </div>
      <div class="footer-right">
        <span v-if="lastUpdated">Last updated: {{ formatTime(lastUpdated) }}</span>
      </div>
    </div>
  </footer>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'

const apiStatus = ref('checking')
const lastUpdated = ref(null)
let healthCheckInterval = null

const statusText = computed(() => {
  switch (apiStatus.value) {
  case 'healthy': return 'Healthy'
  case 'unhealthy': return 'Unhealthy'
  default: return 'Checking...'
  }
})

const statusIcon = computed(() => {
  switch (apiStatus.value) {
  case 'healthy': return 'pi pi-check-circle'
  case 'unhealthy': return 'pi pi-times-circle'
  default: return 'pi pi-spin pi-spinner'
  }
})

const checkHealth = async () => {
  try {
    const response = await fetch('/api/health')
    if (response.ok) {
      apiStatus.value = 'healthy'
      lastUpdated.value = new Date()
    } else {
      apiStatus.value = 'unhealthy'
    }
  } catch (error) {
    apiStatus.value = 'unhealthy'
  }
}

const formatTime = (date) => {
  return new Intl.DateTimeFormat('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

onMounted(() => {
  checkHealth()
  healthCheckInterval = setInterval(checkHealth, 30000)
})

onUnmounted(() => {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval)
  }
})
</script>

<style scoped>
.app-footer {
  background: var(--header-bg);
  color: rgba(255, 255, 255, 0.8);
  padding: var(--spacing-md) var(--spacing-lg);
  font-size: 0.875rem;
}

.footer-content {
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.api-status {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
}

.api-status.healthy {
  color: var(--severity-low);
}

.api-status.unhealthy {
  color: var(--severity-critical);
}

.api-status.checking {
  color: var(--severity-medium);
}

@media (max-width: 768px) {
  .footer-content {
    flex-direction: column;
    gap: var(--spacing-sm);
    text-align: center;
  }
}
</style>
