-- ============================================================================
-- Nubicustos - Database Schema
-- ============================================================================
-- PostgreSQL initialization script
-- This file is automatically executed when the database is first created

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Core Tables
-- ============================================================================

-- Scans metadata table
CREATE TABLE IF NOT EXISTS scans (
    scan_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_type VARCHAR(64) NOT NULL,
    target VARCHAR(256),
    tool VARCHAR(64),
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    status VARCHAR(32) DEFAULT 'running',
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    finding_id VARCHAR(256) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    tool VARCHAR(64) NOT NULL,
    cloud_provider VARCHAR(32),
    account_id VARCHAR(128),
    region VARCHAR(64),
    resource_type VARCHAR(128),
    resource_id VARCHAR(512),
    resource_name VARCHAR(512),
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) DEFAULT 'open',
    title TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    impact TEXT,
    risk_score DECIMAL(4,2),
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(32),
    compliance_frameworks JSONB,
    tags JSONB,
    metadata JSONB,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    scan_date TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    -- Proof of Concept Evidence
    poc_evidence TEXT,
    poc_verification TEXT,
    poc_screenshot_path TEXT,
    -- Enhanced Remediation
    remediation_commands JSONB,
    remediation_code JSONB,
    remediation_resources JSONB
);

-- Compliance mappings table
CREATE TABLE IF NOT EXISTS compliance_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    framework VARCHAR(64) NOT NULL,
    control_id VARCHAR(128) NOT NULL,
    control_title TEXT,
    control_description TEXT,
    requirement TEXT,
    severity VARCHAR(16),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(finding_id, framework, control_id)
);

-- Asset inventory table
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    asset_id VARCHAR(256) UNIQUE NOT NULL,
    cloud_provider VARCHAR(32) NOT NULL,
    account_id VARCHAR(128),
    region VARCHAR(64),
    asset_type VARCHAR(128) NOT NULL,
    asset_name VARCHAR(512),
    tags JSONB,
    metadata JSONB,
    security_findings_count INTEGER DEFAULT 0,
    last_scanned TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Kubernetes resources table
CREATE TABLE IF NOT EXISTS k8s_resources (
    id SERIAL PRIMARY KEY,
    resource_id VARCHAR(256) UNIQUE NOT NULL,
    cluster_name VARCHAR(256),
    namespace VARCHAR(256),
    resource_type VARCHAR(128) NOT NULL,
    resource_name VARCHAR(512),
    labels JSONB,
    annotations JSONB,
    security_context JSONB,
    network_policies JSONB,
    rbac JSONB,
    findings_count INTEGER DEFAULT 0,
    last_scanned TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Container images table
CREATE TABLE IF NOT EXISTS container_images (
    id SERIAL PRIMARY KEY,
    image_id VARCHAR(256) UNIQUE NOT NULL,
    image_name VARCHAR(512) NOT NULL,
    image_tag VARCHAR(128),
    registry VARCHAR(256),
    digest VARCHAR(128),
    size_bytes BIGINT,
    os VARCHAR(64),
    architecture VARCHAR(32),
    vulnerabilities_critical INTEGER DEFAULT 0,
    vulnerabilities_high INTEGER DEFAULT 0,
    vulnerabilities_medium INTEGER DEFAULT 0,
    vulnerabilities_low INTEGER DEFAULT 0,
    last_scanned TIMESTAMP,
    scan_tool VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Attack paths table (for penetration testing attack chain analysis)
CREATE TABLE IF NOT EXISTS attack_paths (
    id SERIAL PRIMARY KEY,
    path_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    name VARCHAR(256) NOT NULL,
    description TEXT,
    entry_point_type VARCHAR(64) NOT NULL,
    entry_point_id VARCHAR(512),
    entry_point_name VARCHAR(256),
    target_type VARCHAR(64) NOT NULL,
    target_description VARCHAR(256),
    nodes JSONB NOT NULL,
    edges JSONB NOT NULL,
    finding_ids INTEGER[],
    risk_score INTEGER NOT NULL DEFAULT 0,
    exploitability VARCHAR(32) NOT NULL DEFAULT 'theoretical',
    impact VARCHAR(32) NOT NULL DEFAULT 'medium',
    hop_count INTEGER NOT NULL DEFAULT 0,
    requires_authentication BOOLEAN DEFAULT FALSE,
    requires_privileges BOOLEAN DEFAULT FALSE,
    poc_available BOOLEAN DEFAULT FALSE,
    poc_steps JSONB,
    mitre_tactics TEXT[],
    aws_services TEXT[],
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ============================================================================
-- Indexes for Performance
-- ============================================================================

-- Findings indexes
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_cloud_provider ON findings(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_findings_resource_type ON findings(resource_type);
CREATE INDEX IF NOT EXISTS idx_findings_scan_date ON findings(scan_date);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);

-- Scans indexes
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type);

-- Asset indexes
CREATE INDEX IF NOT EXISTS idx_assets_cloud_provider ON assets(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_is_active ON assets(is_active);

-- K8s indexes
CREATE INDEX IF NOT EXISTS idx_k8s_cluster ON k8s_resources(cluster_name);
CREATE INDEX IF NOT EXISTS idx_k8s_namespace ON k8s_resources(namespace);
CREATE INDEX IF NOT EXISTS idx_k8s_resource_type ON k8s_resources(resource_type);

-- Container images indexes
CREATE INDEX IF NOT EXISTS idx_images_registry ON container_images(registry);
CREATE INDEX IF NOT EXISTS idx_images_vulnerabilities ON container_images(vulnerabilities_critical, vulnerabilities_high);

-- Attack paths indexes
CREATE INDEX IF NOT EXISTS idx_attack_paths_scan ON attack_paths(scan_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_risk ON attack_paths(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_attack_paths_entry ON attack_paths(entry_point_type);
CREATE INDEX IF NOT EXISTS idx_attack_paths_target ON attack_paths(target_type);
CREATE INDEX IF NOT EXISTS idx_attack_paths_exploitability ON attack_paths(exploitability);

-- ============================================================================
-- Views for Reporting
-- ============================================================================

-- Recent findings summary
CREATE OR REPLACE VIEW recent_findings_summary AS
SELECT 
    cloud_provider,
    tool,
    severity,
    COUNT(*) as count,
    DATE(scan_date) as scan_day
FROM findings
WHERE scan_date > NOW() - INTERVAL '30 days'
GROUP BY cloud_provider, tool, severity, DATE(scan_date)
ORDER BY scan_day DESC, severity;

-- Open findings by severity
CREATE OR REPLACE VIEW open_findings_by_severity AS
SELECT 
    severity,
    cloud_provider,
    COUNT(*) as count,
    ARRAY_AGG(DISTINCT resource_type) as resource_types
FROM findings
WHERE status = 'open'
GROUP BY severity, cloud_provider
ORDER BY 
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END;

-- Top vulnerable resources
CREATE OR REPLACE VIEW top_vulnerable_resources AS
SELECT 
    resource_type,
    cloud_provider,
    COUNT(*) as findings_count,
    COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
    COUNT(*) FILTER (WHERE severity = 'high') as high_count
FROM findings
WHERE status = 'open'
GROUP BY resource_type, cloud_provider
HAVING COUNT(*) > 0
ORDER BY findings_count DESC
LIMIT 20;

-- Compliance framework coverage
CREATE OR REPLACE VIEW compliance_coverage AS
SELECT 
    framework,
    COUNT(DISTINCT control_id) as controls_checked,
    COUNT(DISTINCT finding_id) as findings_count,
    COUNT(DISTINCT finding_id) FILTER (
        WHERE finding_id IN (
            SELECT id FROM findings WHERE status = 'open'
        )
    ) as open_findings
FROM compliance_mappings
GROUP BY framework
ORDER BY framework;

-- ============================================================================
-- Functions
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_k8s_resources_updated_at BEFORE UPDATE ON k8s_resources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_container_images_updated_at BEFORE UPDATE ON container_images
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_attack_paths_updated_at ON attack_paths;
CREATE TRIGGER update_attack_paths_updated_at BEFORE UPDATE ON attack_paths
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Initial Data
-- ============================================================================

-- Insert default scan types
INSERT INTO scans (scan_id, scan_type, target, tool, status, started_at, completed_at) 
VALUES 
    (uuid_generate_v4(), 'initial', 'system', 'initialization', 'completed', NOW(), NOW())
ON CONFLICT DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO auditor;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO auditor;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO auditor;

-- ============================================================================
-- Schema Migrations (for existing databases)
-- ============================================================================

-- Add PoC evidence columns if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='poc_evidence') THEN
        ALTER TABLE findings ADD COLUMN poc_evidence TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='poc_verification') THEN
        ALTER TABLE findings ADD COLUMN poc_verification TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='poc_screenshot_path') THEN
        ALTER TABLE findings ADD COLUMN poc_screenshot_path TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='remediation_commands') THEN
        ALTER TABLE findings ADD COLUMN remediation_commands JSONB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='remediation_code') THEN
        ALTER TABLE findings ADD COLUMN remediation_code JSONB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='remediation_resources') THEN
        ALTER TABLE findings ADD COLUMN remediation_resources JSONB;
    END IF;
    -- Deduplication columns
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='canonical_id') THEN
        ALTER TABLE findings ADD COLUMN canonical_id VARCHAR(256);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='tool_sources') THEN
        ALTER TABLE findings ADD COLUMN tool_sources JSONB DEFAULT '[]';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='affected_resources') THEN
        ALTER TABLE findings ADD COLUMN affected_resources JSONB DEFAULT '[]';
    END IF;
END $$;

-- Create index for canonical_id if not exists
CREATE INDEX IF NOT EXISTS idx_findings_canonical ON findings(canonical_id);

-- ============================================================================
-- Maintenance
-- ============================================================================

-- Vacuum and analyze
VACUUM ANALYZE;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'Database schema initialized successfully';
END $$;
