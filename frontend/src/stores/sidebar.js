import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const STORAGE_KEY = 'nubicustos-sidebar-collapsed'

export const useSidebarStore = defineStore('sidebar', () => {
  // State - load from localStorage
  const collapsed = ref(localStorage.getItem(STORAGE_KEY) === 'true')

  // Computed
  const width = computed(() => collapsed.value ? '60px' : '240px')

  // Actions
  function toggle() {
    collapsed.value = !collapsed.value
    localStorage.setItem(STORAGE_KEY, collapsed.value.toString())
  }

  function expand() {
    collapsed.value = false
    localStorage.setItem(STORAGE_KEY, 'false')
  }

  function collapse() {
    collapsed.value = true
    localStorage.setItem(STORAGE_KEY, 'true')
  }

  return {
    collapsed,
    width,
    toggle,
    expand,
    collapse,
  }
})
