<template>
  <header class="app-header">
    <div class="header-content">
      <div class="logo">
        <div class="logo-icon">
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="32" height="32" rx="8" fill="url(#logo-gradient)"/>
            <path d="M8 16L12 12L16 16L20 12L24 16" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M8 20L12 16L16 20L20 16L24 20" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.6"/>
            <defs>
              <linearGradient id="logo-gradient" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
                <stop stop-color="#6366f1"/>
                <stop offset="1" stop-color="#8b5cf6"/>
              </linearGradient>
            </defs>
          </svg>
        </div>
        <div class="logo-text">
          <h1>Nubicustos</h1>
          <span class="tagline">Security Findings</span>
        </div>
      </div>

      <nav class="nav-links">
        <router-link to="/" class="nav-link" :class="{ active: $route.path === '/' }">
          <i class="pi pi-chart-bar"></i>
          <span>Dashboard</span>
        </router-link>
        <router-link to="/findings" class="nav-link" :class="{ active: $route.path.startsWith('/findings') }">
          <i class="pi pi-list"></i>
          <span>Findings</span>
        </router-link>
        <router-link to="/attack-paths" class="nav-link" :class="{ active: $route.path.startsWith('/attack-paths') }">
          <i class="pi pi-sitemap"></i>
          <span>Attack Paths</span>
        </router-link>
        <a href="/reports/" class="nav-link" target="_blank" rel="noopener">
          <i class="pi pi-folder"></i>
          <span>Reports</span>
        </a>
      </nav>

      <div class="header-actions">
        <button class="theme-toggle" @click="toggleTheme" :title="themeLabel">
          <i :class="themeIcon"></i>
        </button>
        <Dropdown
          v-model="selectedExport"
          :options="exportOptions"
          optionLabel="label"
          placeholder="Export"
          class="export-dropdown"
          @change="handleExport"
        >
          <template #value="{ placeholder }">
            <span class="export-trigger"><i class="pi pi-download"></i> {{ placeholder }}</span>
          </template>
        </Dropdown>
      </div>
    </div>
  </header>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useToast } from 'primevue/usetoast'
import { useThemeStore } from '../../stores/theme'

const toast = useToast()
const themeStore = useThemeStore()
const selectedExport = ref(null)

const exportOptions = [
  { label: 'Export CSV', value: 'csv' },
  { label: 'Export JSON', value: 'json' },
  { label: 'Export PDF', value: 'pdf' }
]

const themeIcon = computed(() => {
  if (themeStore.theme === 'system') return 'pi pi-desktop'
  if (themeStore.theme === 'dark') return 'pi pi-moon'
  return 'pi pi-sun'
})

const themeLabel = computed(() => {
  if (themeStore.theme === 'system') return 'Theme: System'
  if (themeStore.theme === 'dark') return 'Theme: Dark'
  return 'Theme: Light'
})

const toggleTheme = () => {
  themeStore.toggle()
}

const handleExport = (event) => {
  const format = event.value?.value
  if (!format) return

  if (format === 'csv') {
    window.open('/api/exports/csv', '_blank')
  } else if (format === 'json') {
    window.open('/api/exports/json', '_blank')
  } else if (format === 'pdf') {
    toast.add({
      severity: 'info',
      summary: 'PDF Export',
      detail: 'PDF export will be available soon',
      life: 3000
    })
  }

  // Reset selection
  selectedExport.value = null
}
</script>

<style scoped>
.app-header {
  background: var(--header-bg);
  color: white;
  padding: var(--spacing-md) var(--spacing-lg);
  border-bottom: 1px solid var(--header-border);
  position: sticky;
  top: 0;
  z-index: 100;
  backdrop-filter: blur(10px);
}

.header-content {
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-lg);
}

.logo {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.logo-icon {
  flex-shrink: 0;
}

.logo-text h1 {
  font-size: 1.25rem;
  font-weight: 700;
  margin: 0;
  color: white;
  letter-spacing: -0.02em;
}

.logo-text .tagline {
  font-size: 0.75rem;
  opacity: 0.7;
  display: block;
}

.nav-links {
  display: flex;
  gap: var(--spacing-xs);
}

.nav-link {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  color: rgba(255, 255, 255, 0.7);
  text-decoration: none;
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--radius-md);
  transition: all var(--transition-fast);
  font-size: 0.875rem;
  font-weight: 500;
}

.nav-link:hover {
  color: white;
  background: rgba(255, 255, 255, 0.1);
}

.nav-link.active {
  color: white;
  background: rgba(255, 255, 255, 0.15);
}

.nav-link i {
  font-size: 1rem;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.theme-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: var(--radius-md);
  border: 1px solid rgba(255, 255, 255, 0.2);
  background: rgba(255, 255, 255, 0.1);
  color: white;
  cursor: pointer;
  transition: all var(--transition-fast);
}

.theme-toggle:hover {
  background: rgba(255, 255, 255, 0.2);
  border-color: rgba(255, 255, 255, 0.3);
}

.theme-toggle i {
  font-size: 1rem;
}

.export-dropdown {
  background: rgba(255, 255, 255, 0.1) !important;
  border: 1px solid rgba(255, 255, 255, 0.2) !important;
  border-radius: var(--radius-md) !important;
  min-width: 120px;
}

.export-dropdown :deep(.p-dropdown-label) {
  color: white !important;
  padding: var(--spacing-sm) var(--spacing-md);
  font-size: 0.875rem;
}

.export-dropdown :deep(.p-dropdown-trigger) {
  color: white !important;
}

.export-trigger {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

@media (max-width: 768px) {
  .header-content {
    flex-direction: column;
    gap: var(--spacing-md);
  }

  .nav-links {
    flex-wrap: wrap;
    justify-content: center;
  }

  .nav-link span {
    display: none;
  }

  .logo-text .tagline {
    display: none;
  }
}
</style>
