const API_BASE = '/api'

class ApiError extends Error {
  constructor(message, status, data) {
    super(message)
    this.status = status
    this.data = data
  }
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`

  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  }

  try {
    const response = await fetch(url, config)

    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      throw new ApiError(
        data.detail || `HTTP error ${response.status}`,
        response.status,
        data,
      )
    }

    // Handle empty responses
    const text = await response.text()
    return text ? JSON.parse(text) : null
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    throw new ApiError(error.message, 0, null)
  }
}

export const api = {
  // Findings
  async getFindings(params = {}) {
    const searchParams = new URLSearchParams()

    if (params.page) searchParams.set('page', params.page)
    if (params.page_size) searchParams.set('page_size', params.page_size)
    if (params.severity) searchParams.set('severity', params.severity)
    if (params.status) searchParams.set('status', params.status)
    if (params.tool) searchParams.set('tool', params.tool)
    if (params.cloud_provider) searchParams.set('cloud_provider', params.cloud_provider)
    if (params.resource_type) searchParams.set('resource_type', params.resource_type)
    if (params.search) searchParams.set('search', params.search)
    if (params.sort_by) searchParams.set('sort_by', params.sort_by)
    if (params.sort_order) searchParams.set('sort_order', params.sort_order)

    const query = searchParams.toString()
    return request(`/findings${query ? `?${query}` : ''}`)
  },

  async getFinding(id) {
    return request(`/findings/${id}`)
  },

  async getSummary() {
    return request('/findings/summary')
  },

  async getTrend(days = 30) {
    return request(`/findings/trend?days=${days}`)
  },

  async updateFinding(id, data) {
    return request(`/findings/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    })
  },

  // Scans
  async getScans(params = {}) {
    const searchParams = new URLSearchParams()
    if (params.page) searchParams.set('page', params.page)
    if (params.page_size) searchParams.set('page_size', params.page_size)
    if (params.status) searchParams.set('status', params.status)
    if (params.tool) searchParams.set('tool', params.tool)

    const query = searchParams.toString()
    return request(`/scans${query ? `?${query}` : ''}`)
  },

  async getScan(id) {
    return request(`/scans/${id}`)
  },

  async getScanErrors(id) {
    return request(`/scans/${id}/errors`)
  },

  // Exports
  getExportUrl(format, params = {}) {
    const searchParams = new URLSearchParams()

    if (params.severity) searchParams.set('severity', params.severity)
    if (params.status) searchParams.set('status', params.status)
    if (params.tool) searchParams.set('tool', params.tool)
    if (params.include_remediation) searchParams.set('include_remediation', 'true')

    const query = searchParams.toString()
    return `${API_BASE}/exports/${format}${query ? `?${query}` : ''}`
  },

  // Executions
  async getExecutionsHealthSummary(days = 30) {
    return request(`/executions/health/summary?days=${days}`)
  },

  // Health
  async getHealth() {
    return request('/health')
  },

  async getDetailedHealth() {
    return request('/health/detailed')
  },

  // Compliance
  async getComplianceFrameworks() {
    return request('/compliance/frameworks')
  },

  async getComplianceSummary() {
    return request('/compliance/summary')
  },

  async getComplianceFrameworkDetails(framework) {
    return request(`/compliance/frameworks/${encodeURIComponent(framework)}`)
  },

  async getComplianceControlDetails(framework, controlId) {
    return request(`/compliance/frameworks/${encodeURIComponent(framework)}/controls/${encodeURIComponent(controlId)}`)
  },

  getComplianceExportUrl(framework = null) {
    const params = framework ? `?framework=${encodeURIComponent(framework)}` : ''
    return `${API_BASE}/compliance/export/csv${params}`
  },

  // IaC Scanning
  async getIaCProfiles() {
    return request('/iac/profiles')
  },

  async uploadIaCFiles(files) {
    const formData = new FormData()
    for (const file of files) {
      formData.append('files', file)
    }

    const url = `${API_BASE}/iac/upload`

    try {
      const response = await fetch(url, {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new ApiError(
          data.detail || `HTTP error ${response.status}`,
          response.status,
          data,
        )
      }

      return response.json()
    } catch (error) {
      if (error instanceof ApiError) {
        throw error
      }
      throw new ApiError(error.message, 0, null)
    }
  },

  async startIaCScan(scanId, profile = 'iac-quick') {
    return request(`/iac/scan/${scanId}?profile=${encodeURIComponent(profile)}`, {
      method: 'POST',
    })
  },

  async deleteIaCStagingFiles(scanId) {
    return request(`/iac/staging/${scanId}`, {
      method: 'DELETE',
    })
  },
}

export { ApiError }
export default api
