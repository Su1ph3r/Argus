/**
 * Tests for theme store
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useThemeStore } from '../../stores/theme'

describe('Theme Store', () => {
  let store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useThemeStore()
    vi.clearAllMocks()

    // Reset document classes
    document.documentElement.classList.remove('light', 'dark')

    // Reset localStorage mock
    window.localStorage.getItem.mockReturnValue(null)
  })

  describe('Initial State', () => {
    it('should have system as default theme', () => {
      expect(store.theme).toBe('system')
    })

    it('should have systemPrefersDark false initially', () => {
      // Based on our mock matchMedia which returns matches: false
      expect(store.resolvedTheme).toBe('light')
    })
  })

  describe('Computed Properties', () => {
    describe('resolvedTheme', () => {
      it('should return light when theme is light', () => {
        store.theme = 'light'
        expect(store.resolvedTheme).toBe('light')
      })

      it('should return dark when theme is dark', () => {
        store.theme = 'dark'
        expect(store.resolvedTheme).toBe('dark')
      })

      it('should return system preference when theme is system', () => {
        store.theme = 'system'
        // Mock shows system prefers light
        expect(store.resolvedTheme).toBe('light')
      })
    })

    describe('isDark', () => {
      it('should be false for light theme', () => {
        store.theme = 'light'
        expect(store.isDark).toBe(false)
      })

      it('should be true for dark theme', () => {
        store.theme = 'dark'
        expect(store.isDark).toBe(true)
      })
    })
  })

  describe('setTheme', () => {
    it('should update theme value', () => {
      store.setTheme('dark')
      expect(store.theme).toBe('dark')
    })

    it('should save to localStorage', () => {
      store.setTheme('dark')
      expect(window.localStorage.setItem).toHaveBeenCalledWith(
        'nubicustos-theme',
        'dark',
      )
    })

    it('should apply theme to document', () => {
      store.setTheme('dark')
      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('should remove previous theme class', () => {
      document.documentElement.classList.add('light')
      store.setTheme('dark')
      expect(document.documentElement.classList.contains('light')).toBe(false)
    })
  })

  describe('toggle', () => {
    it('should cycle through themes', () => {
      // system -> light
      store.toggle()
      expect(store.theme).toBe('light')

      // light -> dark
      store.toggle()
      expect(store.theme).toBe('dark')

      // dark -> system
      store.toggle()
      expect(store.theme).toBe('system')
    })
  })

  describe('init', () => {
    it('should load saved theme from localStorage', () => {
      window.localStorage.getItem.mockReturnValue('dark')

      store.init()

      expect(store.theme).toBe('dark')
    })

    it('should ignore invalid saved theme', () => {
      window.localStorage.getItem.mockReturnValue('invalid-theme')

      store.init()

      // Should keep default
      expect(store.theme).toBe('system')
    })

    it('should detect system preference', () => {
      store.init()

      // matchMedia was called
      expect(window.matchMedia).toHaveBeenCalledWith('(prefers-color-scheme: dark)')
    })

    it('should apply theme on init', () => {
      window.localStorage.getItem.mockReturnValue('dark')

      store.init()

      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('should accept light theme from localStorage', () => {
      window.localStorage.getItem.mockReturnValue('light')

      store.init()

      expect(store.theme).toBe('light')
    })

    it('should accept system theme from localStorage', () => {
      window.localStorage.getItem.mockReturnValue('system')

      store.init()

      expect(store.theme).toBe('system')
    })
  })

  describe('Theme Application', () => {
    it('should add correct class for light theme', () => {
      store.setTheme('light')
      expect(document.documentElement.classList.contains('light')).toBe(true)
      expect(document.documentElement.classList.contains('dark')).toBe(false)
    })

    it('should add correct class for dark theme', () => {
      store.setTheme('dark')
      expect(document.documentElement.classList.contains('dark')).toBe(true)
      expect(document.documentElement.classList.contains('light')).toBe(false)
    })
  })
})
