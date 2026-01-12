/**
 * Tests for attackPaths store
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAttackPathsStore } from '../../stores/attackPaths'

describe('Attack Paths Store', () => {
  let store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useAttackPathsStore()
    vi.clearAllMocks()
  })

  describe('Initial State', () => {
    it('should have empty paths array', () => {
      expect(store.paths).toEqual([])
    })

    it('should have null current path', () => {
      expect(store.currentPath).toBeNull()
    })

    it('should have null summary', () => {
      expect(store.summary).toBeNull()
    })

    it('should not be loading initially', () => {
      expect(store.loading).toBe(false)
    })

    it('should have no error initially', () => {
      expect(store.error).toBeNull()
    })

    it('should have default pagination', () => {
      expect(store.pagination.page).toBe(1)
      expect(store.pagination.pageSize).toBe(20)
      expect(store.pagination.total).toBe(0)
    })

    it('should have empty filters', () => {
      expect(store.filters.minRiskScore).toBeNull()
      expect(store.filters.maxRiskScore).toBeNull()
      expect(store.filters.exploitability).toBeNull()
    })
  })

  describe('Computed Properties', () => {
    describe('criticalPaths', () => {
      it('should return empty array when no paths', () => {
        expect(store.criticalPaths).toEqual([])
      })

      it('should filter paths with risk_score >= 80', () => {
        store.paths = [
          { id: 1, risk_score: 90 },
          { id: 2, risk_score: 70 },
          { id: 3, risk_score: 85 },
        ]

        expect(store.criticalPaths).toHaveLength(2)
        expect(store.criticalPaths.map(p => p.id)).toEqual([1, 3])
      })
    })

    describe('highRiskPaths', () => {
      it('should return empty array when no paths', () => {
        expect(store.highRiskPaths).toEqual([])
      })

      it('should filter paths with 60 <= risk_score < 80', () => {
        store.paths = [
          { id: 1, risk_score: 90 },
          { id: 2, risk_score: 70 },
          { id: 3, risk_score: 50 },
          { id: 4, risk_score: 60 },
        ]

        expect(store.highRiskPaths).toHaveLength(2)
        expect(store.highRiskPaths.map(p => p.id)).toEqual([2, 4])
      })
    })

    describe('hasFilters', () => {
      it('should be false when no filters set', () => {
        expect(store.hasFilters).toBe(false)
      })

      it('should be true when minRiskScore is set', () => {
        store.filters.minRiskScore = 50
        expect(store.hasFilters).toBe(true)
      })

      it('should be true when exploitability is set', () => {
        store.filters.exploitability = 'confirmed'
        expect(store.hasFilters).toBe(true)
      })
    })
  })

  describe('fetchPaths', () => {
    it('should set loading to true during fetch', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: [], total: 0 }),
      })

      const promise = store.fetchPaths()
      expect(store.loading).toBe(true)

      await promise
      expect(store.loading).toBe(false)
    })

    it('should populate paths on success', async () => {
      const mockPaths = [
        { id: 1, name: 'Path 1', risk_score: 80 },
        { id: 2, name: 'Path 2', risk_score: 60 },
      ]
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: mockPaths, total: 2 }),
      })

      await store.fetchPaths()

      expect(store.paths).toEqual(mockPaths)
      expect(store.pagination.total).toBe(2)
    })

    it('should handle API errors', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      })

      await store.fetchPaths()

      expect(store.error).toBe('Failed to fetch attack paths')
    })

    it('should include filters in request', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: [], total: 0 }),
      })

      store.filters.minRiskScore = 70
      store.filters.exploitability = 'confirmed'
      await store.fetchPaths()

      const url = global.fetch.mock.calls[0][0]
      expect(url).toContain('min_risk_score=70')
      expect(url).toContain('exploitability=confirmed')
    })
  })

  describe('fetchPath', () => {
    it('should fetch single path by ID', async () => {
      const mockPath = { id: 1, name: 'Test Path' }
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockPath),
      })

      const result = await store.fetchPath(1)

      expect(result).toEqual(mockPath)
      expect(store.currentPath).toEqual(mockPath)
    })

    it('should handle fetch errors', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      })

      const result = await store.fetchPath(999)

      expect(result).toBeNull()
      expect(store.error).toBe('Failed to fetch attack path')
    })
  })

  describe('fetchSummary', () => {
    it('should fetch summary data', async () => {
      const mockSummary = {
        total_paths: 10,
        critical_paths: 3,
        high_risk_paths: 4,
      }
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockSummary),
      })

      const result = await store.fetchSummary()

      expect(result).toEqual(mockSummary)
      expect(store.summary).toEqual(mockSummary)
    })

    it('should return null on error', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      })

      const result = await store.fetchSummary()

      expect(result).toBeNull()
    })
  })

  describe('analyzePaths', () => {
    it('should post analyze request', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths_discovered: 5 }),
      })
      // Mock subsequent fetchPaths and fetchSummary
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: [], total: 0 }),
      })
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ total_paths: 5 }),
      })

      const result = await store.analyzePaths()

      expect(result.paths_discovered).toBe(5)
      expect(global.fetch).toHaveBeenCalledWith(
        '/api/attack-paths/analyze',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ max_depth: 5 }),
        }),
      )
    })

    it('should refresh data after analysis', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths_discovered: 5 }),
      })
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: [{ id: 1 }], total: 1 }),
      })
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ total_paths: 1 }),
      })

      await store.analyzePaths()

      // Should have called fetchPaths and fetchSummary
      expect(global.fetch).toHaveBeenCalledTimes(3)
    })

    it('should throw on analysis error', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      })

      await expect(store.analyzePaths()).rejects.toThrow('Analysis failed')
    })
  })

  describe('exportPath', () => {
    it('should export path in specified format', async () => {
      const mockExport = { format: 'markdown', content: '# Test' }
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockExport),
      })

      const result = await store.exportPath(1, 'markdown')

      expect(result).toEqual(mockExport)
      expect(global.fetch).toHaveBeenCalledWith(
        '/api/attack-paths/1/export?format=markdown',
      )
    })

    it('should default to markdown format', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      })

      await store.exportPath(1)

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/attack-paths/1/export?format=markdown',
      )
    })
  })

  describe('deletePath', () => {
    it('should delete path and remove from state', async () => {
      store.paths = [
        { id: 1, name: 'Path 1' },
        { id: 2, name: 'Path 2' },
      ]
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ message: 'Deleted' }),
      })

      const result = await store.deletePath(1)

      expect(result).toBe(true)
      expect(store.paths).toHaveLength(1)
      expect(store.paths[0].id).toBe(2)
    })

    it('should throw on delete error', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      })

      await expect(store.deletePath(999)).rejects.toThrow('Delete failed')
    })
  })

  describe('Pagination Actions', () => {
    it('setPage should update page and fetch', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: [], total: 0 }),
      })

      store.setPage(3)

      expect(store.pagination.page).toBe(3)
      expect(global.fetch).toHaveBeenCalled()
    })
  })

  describe('Filter Actions', () => {
    it('setFilters should update all filter values', async () => {
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: [], total: 0 }),
      })

      store.setFilters({
        minRiskScore: 50,
        maxRiskScore: 90,
        exploitability: 'confirmed',
        entryPointType: 'public_s3',
        targetType: 'iam_admin',
      })

      expect(store.filters.minRiskScore).toBe(50)
      expect(store.filters.maxRiskScore).toBe(90)
      expect(store.filters.exploitability).toBe('confirmed')
      expect(store.pagination.page).toBe(1)
    })

    it('clearFilters should reset all filters', async () => {
      store.filters = {
        minRiskScore: 50,
        maxRiskScore: 90,
        exploitability: 'confirmed',
        entryPointType: 'public_s3',
        targetType: 'iam_admin',
      }
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ paths: [], total: 0 }),
      })

      store.clearFilters()

      expect(store.filters.minRiskScore).toBeNull()
      expect(store.filters.maxRiskScore).toBeNull()
      expect(store.filters.exploitability).toBeNull()
      expect(store.pagination.page).toBe(1)
    })
  })
})
