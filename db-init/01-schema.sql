-- Database schema for cloud security audits

-- Drop existing tables if needed (for fresh start)
-- DROP TABLE IF EXISTS compliance_summary CASCADE;
-- DROP TABLE IF EXISTS findings CASCADE;
-- DROP TABLE IF EXISTS scan_metadata CASCADE;

-- Scan metadata table
CREATE TABLE IF NOT EXISTS scan_metadata (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) UNIQUE NOT NULL,
    tool VARCHAR(50) NOT NULL,
    cloud_provider VARCHAR(50) NOT NULL,
    scan_date TIMESTAMP NOT NULL,
    duration_seconds INTEGER,
    status VARCHAR(50),
    account_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) REFERENCES scan_metadata(scan_id) ON DELETE CASCADE,
    finding_id VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(100),
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    region VARCHAR(50),
    title TEXT,
    description TEXT,
    remediation TEXT,
    compliance_frameworks JSONB,
    raw_data JSONB,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, finding_id)
);

-- Compliance summary table
CREATE TABLE IF NOT EXISTS compliance_summary (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) REFERENCES scan_metadata(scan_id) ON DELETE CASCADE,
    framework VARCHAR(100) NOT NULL,
    passed INTEGER DEFAULT 0,
    failed INTEGER DEFAULT 0,
    not_applicable INTEGER DEFAULT 0,
    compliance_score DECIMAL(5,2),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Remediation tracking table
CREATE TABLE IF NOT EXISTS remediation_tracking (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL,
    assigned_to VARCHAR(255),
    priority VARCHAR(20),
    notes TEXT,
    due_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit history table
CREATE TABLE IF NOT EXISTS audit_history (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255),
    action VARCHAR(100),
    performed_by VARCHAR(255),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_resource ON findings(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_findings_region ON findings(region);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_scan_metadata_date ON scan_metadata(scan_date);
CREATE INDEX IF NOT EXISTS idx_scan_metadata_provider ON scan_metadata(cloud_provider);

-- Create views for common queries
CREATE OR REPLACE VIEW v_findings_summary AS
SELECT 
    s.scan_id,
    s.tool,
    s.cloud_provider,
    s.scan_date,
    COUNT(f.id) as total_findings,
    COUNT(CASE WHEN f.severity = 'CRITICAL' THEN 1 END) as critical,
    COUNT(CASE WHEN f.severity = 'HIGH' THEN 1 END) as high,
    COUNT(CASE WHEN f.severity = 'MEDIUM' THEN 1 END) as medium,
    COUNT(CASE WHEN f.severity = 'LOW' THEN 1 END) as low,
    COUNT(CASE WHEN f.severity = 'INFO' THEN 1 END) as info
FROM scan_metadata s
LEFT JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.scan_id, s.tool, s.cloud_provider, s.scan_date
ORDER BY s.scan_date DESC;

CREATE OR REPLACE VIEW v_recent_critical_findings AS
SELECT 
    f.finding_id,
    f.title,
    f.resource_id,
    f.region,
    f.description,
    s.tool,
    s.cloud_provider,
    s.scan_date
FROM findings f
JOIN scan_metadata s ON f.scan_id = s.scan_id
WHERE f.severity = 'CRITICAL'
AND s.scan_date > NOW() - INTERVAL '7 days'
ORDER BY s.scan_date DESC;

-- Functions for reporting
CREATE OR REPLACE FUNCTION get_compliance_trend(
    p_framework VARCHAR,
    p_days INTEGER DEFAULT 30
) RETURNS TABLE (
    scan_date DATE,
    compliance_score DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        DATE(s.scan_date) as scan_date,
        c.compliance_score
    FROM compliance_summary c
    JOIN scan_metadata s ON c.scan_id = s.scan_id
    WHERE c.framework = p_framework
    AND s.scan_date > NOW() - INTERVAL '1 day' * p_days
    ORDER BY s.scan_date;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_scan_metadata_updated_at BEFORE UPDATE ON scan_metadata
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_remediation_tracking_updated_at BEFORE UPDATE ON remediation_tracking
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
