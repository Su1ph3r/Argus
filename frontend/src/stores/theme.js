import { defineStore } from 'pinia'
import { ref, watch, computed } from 'vue'

export const useThemeStore = defineStore('theme', () => {
  // State
  const theme = ref('system') // 'light' | 'dark' | 'system'
  const style = ref('modern') // 'modern' | 'classic'
  const systemPrefersDark = ref(false)

  // Store reference to media query and handler for cleanup
  let mediaQuery = null
  let mediaQueryHandler = null

  // Computed
  const resolvedTheme = computed(() => {
    if (theme.value === 'system') {
      return systemPrefersDark.value ? 'dark' : 'light'
    }
    return theme.value
  })

  const isDark = computed(() => resolvedTheme.value === 'dark')
  const isClassic = computed(() => style.value === 'classic')

  // Actions
  function setTheme(newTheme) {
    theme.value = newTheme
    localStorage.setItem('nubicustos-theme', newTheme)
    applyTheme()
  }

  function setStyle(newStyle) {
    style.value = newStyle
    localStorage.setItem('nubicustos-style', newStyle)
    applyStyle()
  }

  function toggle() {
    const themes = ['system', 'light', 'dark']
    const currentIndex = themes.indexOf(theme.value)
    const nextIndex = (currentIndex + 1) % themes.length
    setTheme(themes[nextIndex])
  }

  function applyTheme() {
    const html = document.documentElement
    html.classList.remove('light', 'dark')
    html.classList.add(resolvedTheme.value)
  }

  function applyStyle() {
    const html = document.documentElement
    html.classList.remove('theme-classic')
    if (style.value === 'classic') {
      html.classList.add('theme-classic')
    }
  }

  function detectSystem() {
    // Clean up previous listener if exists
    if (mediaQuery && mediaQueryHandler) {
      mediaQuery.removeEventListener('change', mediaQueryHandler)
    }

    mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    systemPrefersDark.value = mediaQuery.matches

    // Store handler reference for cleanup
    mediaQueryHandler = (e) => {
      systemPrefersDark.value = e.matches
      if (theme.value === 'system') {
        applyTheme()
      }
    }

    mediaQuery.addEventListener('change', mediaQueryHandler)
  }

  function cleanup() {
    // Remove event listener to prevent memory leaks
    if (mediaQuery && mediaQueryHandler) {
      mediaQuery.removeEventListener('change', mediaQueryHandler)
      mediaQuery = null
      mediaQueryHandler = null
    }
  }

  function init() {
    // Load saved theme preference
    const saved = localStorage.getItem('nubicustos-theme')
    if (saved && ['light', 'dark', 'system'].includes(saved)) {
      theme.value = saved
    }

    // Load saved style preference
    const savedStyle = localStorage.getItem('nubicustos-style')
    if (savedStyle && ['modern', 'classic'].includes(savedStyle)) {
      style.value = savedStyle
    }

    // Detect system preference
    detectSystem()

    // Apply initial theme and style
    applyTheme()
    applyStyle()
  }

  // Watch for theme changes
  watch(resolvedTheme, () => {
    applyTheme()
  })

  return {
    theme,
    style,
    resolvedTheme,
    isDark,
    isClassic,
    setTheme,
    setStyle,
    toggle,
    init,
    cleanup,
  }
})
