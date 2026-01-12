<template>
  <div
    class="app-container"
    :class="{ 'sidebar-collapsed': sidebarStore.collapsed }"
  >
    <AppSidebar />
    <div class="app-main">
      <main class="main-content">
        <router-view />
      </main>
      <AppFooter />
    </div>
    <Toast />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import AppSidebar from './components/layout/AppSidebar.vue'
import AppFooter from './components/layout/AppFooter.vue'
import { useThemeStore } from './stores/theme'
import { useSidebarStore } from './stores/sidebar'
import { useCredentialsStore } from './stores/credentials'

const themeStore = useThemeStore()
const sidebarStore = useSidebarStore()
const credentialsStore = useCredentialsStore()

onMounted(() => {
  themeStore.init()
  // Restore previously selected AWS profile
  credentialsStore.restoreAwsProfile()
})
</script>

<style scoped>
.app-container {
  min-height: 100vh;
  display: flex;
  background: var(--bg-primary);
  overflow-x: hidden;
}

.app-main {
  flex: 1;
  margin-left: 240px;
  display: flex;
  flex-direction: column;
  transition: margin-left 0.2s ease;
  min-width: 0;
  width: calc(100vw - 240px);
  max-width: calc(100vw - 240px);
}

.app-container.sidebar-collapsed .app-main {
  margin-left: 60px;
  width: calc(100vw - 60px);
  max-width: calc(100vw - 60px);
}

.main-content {
  flex: 1;
  padding: var(--spacing-lg);
  background: var(--bg-primary);
  min-width: 0;
  overflow-x: auto;
}
</style>
