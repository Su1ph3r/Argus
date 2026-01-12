/**
 * Tests for findings store
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useFindingsStore } from '../../stores/findings'

// Mock the API module
vi.mock('../../services/api', () => ({
  default: {
    getFindings: vi.fn(),
    getFinding: vi.fn(),
    updateFinding: vi.fn(),
  },
}))

import api from '../../services/api'

describe('Findings Store', () => {
  let store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useFindingsStore()
    vi.clearAllMocks()
  })

  describe('Initial State', () => {
    it('should have empty findings array', () => {
      expect(store.findings).toEqual([])
    })

    it('should have null current finding', () => {
      expect(store.currentFinding).toBeNull()
    })

    it('should have default pagination values', () => {
      expect(store.page).toBe(1)
      expect(store.pageSize).toBe(50)
      expect(store.total).toBe(0)
    })

    it('should not be loading initially', () => {
      expect(store.loading).toBe(false)
    })

    it('should have empty filters', () => {
      expect(store.filters.severity).toBeNull()
      expect(store.filters.status).toBeNull()
      expect(store.filters.search).toBe('')
    })

    it('should have default filter options', () => {
      expect(store.filterOptions.severities).toContain('critical')
      expect(store.filterOptions.statuses).toContain('open')
    })
  })

  describe('Computed Properties', () => {
    it('hasFilters should be false when no filters set', () => {
      expect(store.hasFilters).toBe(false)
    })

    it('hasFilters should be true when filters are set', () => {
      store.setFilter('severity', 'critical')
      expect(store.hasFilters).toBe(true)
    })

    it('totalPages should calculate correctly', () => {
      store.total = 150
      store.pageSize = 50
      expect(store.totalPages).toBe(3)
    })

    it('totalPages should round up', () => {
      store.total = 101
      store.pageSize = 50
      expect(store.totalPages).toBe(3)
    })
  })

  describe('fetchFindings', () => {
    it('should set loading to true during fetch', async () => {
      api.getFindings.mockResolvedValue({ findings: [], total: 0 })

      const promise = store.fetchFindings()
      expect(store.loading).toBe(true)

      await promise
      expect(store.loading).toBe(false)
    })

    it('should populate findings on success', async () => {
      const mockFindings = [
        { id: 1, title: 'Finding 1', severity: 'high' },
        { id: 2, title: 'Finding 2', severity: 'medium' },
      ]
      api.getFindings.mockResolvedValue({ findings: mockFindings, total: 2 })

      await store.fetchFindings()

      expect(store.findings).toEqual(mockFindings)
      expect(store.total).toBe(2)
    })

    it('should handle API errors', async () => {
      api.getFindings.mockRejectedValue(new Error('Network error'))

      await store.fetchFindings()

      expect(store.error).toBe('Network error')
      expect(store.findings).toEqual([])
      expect(store.total).toBe(0)
    })

    it('should pass filters to API', async () => {
      api.getFindings.mockResolvedValue({ findings: [], total: 0 })

      store.setFilter('severity', 'critical')
      store.setFilter('status', 'open')
      await store.fetchFindings()

      expect(api.getFindings).toHaveBeenCalledWith(
        expect.objectContaining({
          severity: 'critical',
          status: 'open',
        }),
      )
    })

    it('should not pass null filter values to API', async () => {
      api.getFindings.mockResolvedValue({ findings: [], total: 0 })

      await store.fetchFindings()

      const callArgs = api.getFindings.mock.calls[0][0]
      expect(callArgs).not.toHaveProperty('severity')
    })
  })

  describe('fetchFinding', () => {
    it('should fetch single finding by ID', async () => {
      const mockFinding = { id: 1, title: 'Test Finding' }
      api.getFinding.mockResolvedValue(mockFinding)

      await store.fetchFinding(1)

      expect(api.getFinding).toHaveBeenCalledWith(1)
      expect(store.currentFinding).toEqual(mockFinding)
    })

    it('should handle fetch errors', async () => {
      api.getFinding.mockRejectedValue(new Error('Not found'))

      await store.fetchFinding(999)

      expect(store.error).toBe('Not found')
      expect(store.currentFinding).toBeNull()
    })
  })

  describe('updateFinding', () => {
    beforeEach(() => {
      store.findings = [
        { id: 1, title: 'Finding 1', status: 'open' },
        { id: 2, title: 'Finding 2', status: 'open' },
      ]
    })

    it('should update finding in local state', async () => {
      api.updateFinding.mockResolvedValue({ id: 1, status: 'closed' })

      await store.updateFinding(1, { status: 'closed' })

      expect(store.findings[0].status).toBe('closed')
    })

    it('should update current finding if same ID', async () => {
      store.currentFinding = { id: 1, title: 'Finding 1', status: 'open' }
      api.updateFinding.mockResolvedValue({ id: 1, status: 'closed' })

      await store.updateFinding(1, { status: 'closed' })

      expect(store.currentFinding.status).toBe('closed')
    })

    it('should throw on update error', async () => {
      api.updateFinding.mockRejectedValue(new Error('Update failed'))

      await expect(store.updateFinding(1, {})).rejects.toThrow('Update failed')
    })
  })

  describe('Filter Actions', () => {
    it('setFilter should update filter value', () => {
      store.setFilter('severity', 'high')
      expect(store.filters.severity).toBe('high')
    })

    it('setFilter should reset page to 1', () => {
      store.page = 5
      store.setFilter('severity', 'high')
      expect(store.page).toBe(1)
    })

    it('clearFilters should reset all filters', () => {
      store.setFilter('severity', 'critical')
      store.setFilter('status', 'open')
      store.setFilter('search', 'test')
      store.page = 5

      store.clearFilters()

      expect(store.filters.severity).toBeNull()
      expect(store.filters.status).toBeNull()
      expect(store.filters.search).toBe('')
      expect(store.page).toBe(1)
    })
  })

  describe('Pagination Actions', () => {
    it('setPage should update page', () => {
      store.setPage(3)
      expect(store.page).toBe(3)
    })

    it('setPageSize should update page size and reset page', () => {
      store.page = 5
      store.setPageSize(100)
      expect(store.pageSize).toBe(100)
      expect(store.page).toBe(1)
    })
  })
})
