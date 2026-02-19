<template>
  <aside
    class="app-sidebar"
    :class="{ collapsed: sidebarStore.collapsed }"
  >
    <!-- Logo Section -->
    <div class="sidebar-header">
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
            fill="url(#logo-gradient-sidebar)"
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
              id="logo-gradient-sidebar"
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
      <span
        v-if="!sidebarStore.collapsed"
        class="logo-text"
      >Nubicustos</span>
      <button
        class="collapse-btn"
        :title="sidebarStore.collapsed ? 'Expand' : 'Collapse'"
        @click="sidebarStore.toggle"
      >
        <i :class="sidebarStore.collapsed ? 'pi pi-angle-right' : 'pi pi-angle-left'" />
      </button>
    </div>

    <!-- Navigation Items -->
    <nav class="sidebar-nav">
      <!-- Primary: Scans -->
      <router-link
        to="/scans"
        class="nav-item"
        :class="{ active: $route.path.startsWith('/scans') }"
        :title="sidebarStore.collapsed ? 'Scans' : ''"
      >
        <i class="pi pi-play" />
        <span v-if="!sidebarStore.collapsed">Scans</span>
      </router-link>

      <!-- Credentials -->
      <router-link
        to="/credentials"
        class="nav-item"
        :class="{ active: $route.path === '/credentials' }"
        :title="sidebarStore.collapsed ? 'Credentials' : ''"
      >
        <i class="pi pi-key" />
        <span v-if="!sidebarStore.collapsed">Credentials</span>
      </router-link>

      <!-- Dashboard -->
      <router-link
        to="/"
        class="nav-item"
        :class="{ active: $route.path === '/' }"
        :title="sidebarStore.collapsed ? 'Dashboard' : ''"
      >
        <i class="pi pi-chart-bar" />
        <span v-if="!sidebarStore.collapsed">Dashboard</span>
      </router-link>

      <!-- Findings -->
      <router-link
        to="/findings"
        class="nav-item"
        :class="{ active: $route.path.startsWith('/findings') }"
        :title="sidebarStore.collapsed ? 'Findings' : ''"
      >
        <i class="pi pi-list" />
        <span v-if="!sidebarStore.collapsed">Findings</span>
      </router-link>

      <!-- Compliance -->
      <router-link
        to="/compliance"
        class="nav-item"
        :class="{ active: $route.path === '/compliance' }"
        :title="sidebarStore.collapsed ? 'Compliance' : ''"
      >
        <i class="pi pi-verified" />
        <span v-if="!sidebarStore.collapsed">Compliance</span>
      </router-link>

      <!-- Attack Paths -->
      <router-link
        to="/attack-paths"
        class="nav-item"
        :class="{ active: $route.path.startsWith('/attack-paths') }"
        :title="sidebarStore.collapsed ? 'Attack Paths' : ''"
      >
        <i class="pi pi-sitemap" />
        <span v-if="!sidebarStore.collapsed">Attack Paths</span>
      </router-link>

      <!-- Pentest Submenu -->
      <div class="nav-group">
        <button
          class="nav-item nav-group-header"
          :class="{ active: isPentestRouteActive }"
          :title="sidebarStore.collapsed ? 'Pentest' : ''"
          @click="togglePentest"
        >
          <i class="pi pi-shield" />
          <span v-if="!sidebarStore.collapsed">Pentest</span>
          <i
            v-if="!sidebarStore.collapsed"
            :class="pentestOpen ? 'pi pi-chevron-up' : 'pi pi-chevron-down'"
            class="chevron"
          />
        </button>
        <div
          v-if="pentestOpen && !sidebarStore.collapsed"
          class="nav-submenu"
        >
          <router-link
            to="/public-exposures"
            class="nav-subitem"
          >
            <i class="pi pi-globe" /> Public Exposures
          </router-link>
          <router-link
            to="/exposed-credentials"
            class="nav-subitem"
          >
            <i class="pi pi-key" /> Exposed Credentials
          </router-link>
          <router-link
            to="/severity-overrides"
            class="nav-subitem"
          >
            <i class="pi pi-sliders-h" /> Severity Overrides
          </router-link>
          <router-link
            to="/privesc-paths"
            class="nav-subitem"
          >
            <i class="pi pi-arrow-up-right" /> Privesc Paths
          </router-link>
          <router-link
            to="/imds-checks"
            class="nav-subitem"
          >
            <i class="pi pi-server" /> IMDS Checks
          </router-link>
          <router-link
            to="/cloudfox"
            class="nav-subitem"
          >
            <i class="pi pi-search" /> CloudFox
          </router-link>
          <router-link
            to="/pacu"
            class="nav-subitem"
          >
            <i class="pi pi-bolt" /> Pacu
          </router-link>
          <router-link
            to="/enumerate-iam"
            class="nav-subitem"
          >
            <i class="pi pi-id-card" /> enumerate-iam
          </router-link>
          <router-link
            to="/assumed-roles"
            class="nav-subitem"
          >
            <i class="pi pi-share-alt" /> Assumed Roles
          </router-link>
          <router-link
            to="/lambda-analysis"
            class="nav-subitem"
          >
            <i class="pi pi-code" /> Lambda Analysis
          </router-link>
        </div>
      </div>

      <!-- Settings -->
      <router-link
        to="/settings"
        class="nav-item"
        :class="{ active: $route.path === '/settings' }"
        :title="sidebarStore.collapsed ? 'Settings' : ''"
      >
        <i class="pi pi-cog" />
        <span v-if="!sidebarStore.collapsed">Settings</span>
      </router-link>

      <!-- Reports (external) -->
      <a
        href="/reports/"
        target="_blank"
        rel="noopener"
        class="nav-item"
        :title="sidebarStore.collapsed ? 'Reports' : ''"
      >
        <i class="pi pi-external-link" />
        <span v-if="!sidebarStore.collapsed">Reports</span>
      </a>
    </nav>

    <!-- Footer actions -->
    <div class="sidebar-footer">
      <button
        class="nav-item"
        :title="themeLabel"
        @click="toggleTheme"
      >
        <i :class="themeIcon" />
        <span v-if="!sidebarStore.collapsed">{{ themeLabel }}</span>
      </button>
      <button
        class="nav-item"
        :title="sidebarStore.collapsed ? 'Export' : ''"
        @click="exportFindings"
      >
        <i class="pi pi-download" />
        <span v-if="!sidebarStore.collapsed">Export</span>
      </button>
    </div>
  </aside>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useSidebarStore } from '../../stores/sidebar'
import { useThemeStore } from '../../stores/theme'

const route = useRoute()
const sidebarStore = useSidebarStore()
const themeStore = useThemeStore()

const pentestOpen = ref(false)

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

const isPentestRouteActive = computed(() => {
  return pentestRoutes.some(r => route.path.startsWith(r))
})

const themeIcon = computed(() => {
  if (themeStore.theme === 'system') return 'pi pi-desktop'
  if (themeStore.theme === 'dark') return 'pi pi-moon'
  return 'pi pi-sun'
})

const themeLabel = computed(() => {
  if (themeStore.theme === 'system') return 'System'
  if (themeStore.theme === 'dark') return 'Dark'
  return 'Light'
})

function togglePentest() {
  if (sidebarStore.collapsed) {
    sidebarStore.expand()
    pentestOpen.value = true
  } else {
    pentestOpen.value = !pentestOpen.value
  }
}

function toggleTheme() {
  themeStore.toggle()
}

function exportFindings() {
  window.open('/api/exports/json', '_blank')
}
</script>

<style scoped>
.app-sidebar {
  position: fixed;
  left: 0;
  top: 0;
  height: 100vh;
  width: 240px;
  background: var(--header-bg);
  border-right: 1px solid var(--header-border);
  display: flex;
  flex-direction: column;
  transition: width 0.2s ease;
  z-index: 100;
}

.app-sidebar.collapsed {
  width: 60px;
}

/* Header */
.sidebar-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.logo-icon {
  flex-shrink: 0;
}

.logo-text {
  font-size: 1.125rem;
  font-weight: 700;
  color: white;
  white-space: nowrap;
  overflow: hidden;
}

.collapse-btn {
  margin-left: auto;
  width: 28px;
  height: 28px;
  border-radius: 6px;
  border: 1px solid rgba(255, 255, 255, 0.2);
  background: rgba(255, 255, 255, 0.1);
  color: white;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s;
}

.collapse-btn:hover {
  background: rgba(255, 255, 255, 0.2);
}

.collapsed .collapse-btn {
  margin-left: 0;
}

/* Navigation */
.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  padding: 12px 8px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  color: rgba(255, 255, 255, 0.7);
  text-decoration: none;
  border-radius: 8px;
  margin-bottom: 4px;
  transition: all 0.15s;
  font-size: 0.875rem;
  font-weight: 500;
  border: none;
  background: transparent;
  width: 100%;
  cursor: pointer;
  text-align: left;
}

.nav-item:hover {
  background: rgba(255, 255, 255, 0.1);
  color: white;
}

.nav-item.active {
  background: rgba(255, 255, 255, 0.15);
  color: white;
}

.nav-item i:first-child {
  font-size: 1rem;
  width: 20px;
  text-align: center;
  flex-shrink: 0;
}

.collapsed .nav-item {
  justify-content: center;
  padding: 10px;
}

.collapsed .nav-item span,
.collapsed .nav-item .chevron {
  display: none;
}

/* Pentest submenu */
.nav-group {
  margin-bottom: 4px;
}

.nav-group-header {
  position: relative;
}

.chevron {
  margin-left: auto;
  font-size: 0.75rem;
}

.nav-submenu {
  padding-left: 20px;
  margin-top: 4px;
}

.nav-subitem {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  color: rgba(255, 255, 255, 0.6);
  text-decoration: none;
  border-radius: 6px;
  margin-bottom: 2px;
  transition: all 0.15s;
  font-size: 0.8125rem;
}

.nav-subitem:hover {
  background: rgba(255, 255, 255, 0.08);
  color: rgba(255, 255, 255, 0.9);
}

.nav-subitem.router-link-active {
  background: rgba(255, 255, 255, 0.1);
  color: white;
}

.nav-subitem i {
  font-size: 0.8125rem;
  width: 16px;
  text-align: center;
}

/* Footer */
.sidebar-footer {
  padding: 12px 8px;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
}

/* Scrollbar */
.sidebar-nav::-webkit-scrollbar {
  width: 4px;
}

.sidebar-nav::-webkit-scrollbar-track {
  background: transparent;
}

.sidebar-nav::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 2px;
}

.sidebar-nav::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}
</style>
