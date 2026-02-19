<template>
  <header class="app-header">
    <div class="header-content">
      <div class="logo">
        <div class="logo-icon">
          <svg
            width="32"
            height="32"
            viewBox="0 0 32 32"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <rect
              width="32"
              height="32"
              rx="8"
              fill="url(#logo-gradient)"
            />
            <path
              d="M8 16L12 12L16 16L20 12L24 16"
              stroke="white"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <path
              d="M8 20L12 16L16 20L20 16L24 20"
              stroke="white"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              opacity="0.6"
            />
            <defs>
              <linearGradient
                id="logo-gradient"
                x1="0"
                y1="0"
                x2="32"
                y2="32"
                gradientUnits="userSpaceOnUse"
              >
                <stop stop-color="#3b82f6" />
                <stop
                  offset="1"
                  stop-color="#2563eb"
                />
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
        <router-link
          to="/"
          class="nav-link"
          :class="{ active: $route.path === '/' }"
        >
          <i class="pi pi-chart-bar" />
          <span>Dashboard</span>
        </router-link>
        <router-link
          to="/findings"
          class="nav-link"
          :class="{ active: $route.path.startsWith('/findings') }"
        >
          <i class="pi pi-list" />
          <span>Findings</span>
        </router-link>
        <router-link
          to="/attack-paths"
          class="nav-link"
          :class="{ active: $route.path.startsWith('/attack-paths') }"
        >
          <i class="pi pi-sitemap" />
          <span>Attack Paths</span>
        </router-link>
        <div
          class="nav-dropdown"
          @mouseenter="showPentestMenu = true"
          @mouseleave="showPentestMenu = false"
        >
          <button
            class="nav-link"
            :class="{ active: isPentestRouteActive }"
          >
            <i class="pi pi-shield" />
            <span>Pentest</span>
            <i class="pi pi-chevron-down dropdown-arrow" />
          </button>
          <div
            v-if="showPentestMenu"
            class="dropdown-menu"
          >
            <router-link
              to="/public-exposures"
              class="dropdown-item"
            >
              <i class="pi pi-globe" /> Public Exposures
            </router-link>
            <router-link
              to="/exposed-credentials"
              class="dropdown-item"
            >
              <i class="pi pi-key" /> Exposed Credentials
            </router-link>
            <router-link
              to="/severity-overrides"
              class="dropdown-item"
            >
              <i class="pi pi-sliders-h" /> Severity Overrides
            </router-link>
            <router-link
              to="/privesc-paths"
              class="dropdown-item"
            >
              <i class="pi pi-arrow-up-right" /> Privesc Paths
            </router-link>
            <router-link
              to="/imds-checks"
              class="dropdown-item"
            >
              <i class="pi pi-server" /> IMDS Checks
            </router-link>
            <div class="dropdown-divider" />
            <router-link
              to="/cloudfox"
              class="dropdown-item"
            >
              <i class="pi pi-search" /> CloudFox
            </router-link>
            <router-link
              to="/pacu"
              class="dropdown-item"
            >
              <i class="pi pi-bolt" /> Pacu
            </router-link>
            <router-link
              to="/enumerate-iam"
              class="dropdown-item"
            >
              <i class="pi pi-id-card" /> enumerate-iam
            </router-link>
            <div class="dropdown-divider" />
            <router-link
              to="/assumed-roles"
              class="dropdown-item"
            >
              <i class="pi pi-share-alt" /> Assumed Roles
            </router-link>
            <router-link
              to="/lambda-analysis"
              class="dropdown-item"
            >
              <i class="pi pi-code" /> Lambda Analysis
            </router-link>
          </div>
        </div>
        <div
          class="nav-dropdown"
          @mouseenter="showConfigMenu = true"
          @mouseleave="showConfigMenu = false"
        >
          <button
            class="nav-link"
            :class="{ active: isConfigRouteActive }"
          >
            <i class="pi pi-cog" />
            <span>Configuration</span>
            <i class="pi pi-chevron-down dropdown-arrow" />
          </button>
          <div
            v-if="showConfigMenu"
            class="dropdown-menu"
          >
            <router-link
              to="/scans"
              class="dropdown-item"
            >
              <i class="pi pi-play" /> Scans
            </router-link>
            <router-link
              to="/credentials"
              class="dropdown-item"
            >
              <i class="pi pi-key" /> Credentials
            </router-link>
            <router-link
              to="/settings"
              class="dropdown-item"
            >
              <i class="pi pi-sliders-h" /> Settings
            </router-link>
          </div>
        </div>
        <a
          href="/reports/"
          class="nav-link"
          target="_blank"
          rel="noopener"
        >
          <i class="pi pi-folder" />
          <span>Reports</span>
        </a>
      </nav>

      <div class="header-actions">
        <button
          class="theme-toggle"
          :title="themeLabel"
          @click="toggleTheme"
        >
          <i :class="themeIcon" />
        </button>
        <Dropdown
          v-model="selectedExport"
          :options="exportOptions"
          option-label="label"
          placeholder="Export"
          class="export-dropdown"
          @change="handleExport"
        >
          <template #value="{ placeholder }">
            <span class="export-trigger"><i class="pi pi-download" /> {{ placeholder }}</span>
          </template>
        </Dropdown>
      </div>
    </div>
  </header>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { useThemeStore } from '../../stores/theme'

const route = useRoute()
const toast = useToast()
const themeStore = useThemeStore()
const selectedExport = ref(null)
const showPentestMenu = ref(false)
const showConfigMenu = ref(false)

const pentestRoutes = [
  '/public-exposures',
  '/exposed-credentials',
  '/severity-overrides',
  '/privesc-paths',
  '/imds-checks',
  '/cloudfox',
  '/pacu',
  '/enumerate-iam',
  '/assumed-roles',
  '/lambda-analysis',
]

const configRoutes = [
  '/scans',
  '/credentials',
  '/settings',
]

const isPentestRouteActive = computed(() => {
  return pentestRoutes.some(r => route.path.startsWith(r))
})

const isConfigRouteActive = computed(() => {
  return configRoutes.some(r => route.path.startsWith(r))
})

const exportOptions = [
  { label: 'Export CSV', value: 'csv' },
  { label: 'Export JSON', value: 'json' },
  { label: 'Export PDF', value: 'pdf' },
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
      life: 3000,
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

.nav-dropdown {
  position: relative;
}

.nav-dropdown .nav-link {
  border: none;
  background: transparent;
  cursor: pointer;
}

.dropdown-arrow {
  font-size: 0.75rem;
  margin-left: 0.25rem;
}

.dropdown-menu {
  position: absolute;
  top: 100%;
  left: 0;
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: var(--radius-md);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
  min-width: 200px;
  padding: 0.5rem 0;
  z-index: 1000;
}

.dropdown-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  color: var(--text-color);
  text-decoration: none;
  font-size: 0.875rem;
  transition: background-color 0.15s;
}

.dropdown-item:hover {
  background: var(--surface-hover);
}

.dropdown-item i {
  font-size: 0.875rem;
  width: 1rem;
  text-align: center;
}

.dropdown-divider {
  height: 1px;
  background: var(--surface-border);
  margin: 0.5rem 0;
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
