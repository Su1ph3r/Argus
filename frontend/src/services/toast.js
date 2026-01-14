/**
 * Centralized toast notification service for Nubicustos.
 *
 * Provides a single point of control for all toast notifications across
 * the application. Initialize once in App.vue, use anywhere via imports.
 */

// Global toast instance (set from App.vue)
let toastInstance = null

/**
 * Set the PrimeVue toast instance.
 * Call this once from App.vue during initialization.
 * @param {Object} toast - PrimeVue toast from useToast()
 */
export function setToastInstance(toast) {
  toastInstance = toast
}

/**
 * Show a toast notification.
 * @param {string} severity - 'success' | 'info' | 'warn' | 'error'
 * @param {string} summary - Toast title
 * @param {string} detail - Toast message body
 * @param {number} life - Duration in ms (default 4000)
 */
function showToast(severity, summary, detail, life = 4000) {
  if (toastInstance) {
    toastInstance.add({ severity, summary, detail, life })
  } else {
    // Fallback to console if toast not available (e.g., during SSR or tests)
    const logFn = severity === 'error' ? console.error : console.warn
    logFn(`[Toast ${severity}] ${summary}: ${detail}`)
  }
}

/**
 * Toast notification helpers.
 * Import and use: toast.success('Title', 'Message')
 */
export const toast = {
  /**
   * Show success notification (green)
   */
  success(summary, detail, life = 4000) {
    showToast('success', summary, detail, life)
  },

  /**
   * Show info notification (blue)
   */
  info(summary, detail, life = 4000) {
    showToast('info', summary, detail, life)
  },

  /**
   * Show warning notification (yellow)
   */
  warn(summary, detail, life = 4000) {
    showToast('warn', summary, detail, life)
  },

  /**
   * Show error notification (red)
   * Default 5000ms to give user more time to read errors
   */
  error(summary, detail, life = 5000) {
    showToast('error', summary, detail, life)
  },

  /**
   * Show error from API response.
   * Extracts meaningful message from ApiError or uses fallback.
   * @param {Error|ApiError} error - Error object
   * @param {string} fallbackMessage - Default message if error has no detail
   */
  apiError(error, fallbackMessage = 'An error occurred') {
    const message = error?.message || error?.data?.detail || fallbackMessage
    showToast('error', 'Error', message, 5000)
  },
}

export default toast
