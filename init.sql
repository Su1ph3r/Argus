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

-- Scan files tracking table (for bulk delete/archive operations)
CREATE TABLE IF NOT EXISTS scan_files (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    tool VARCHAR(64) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_type VARCHAR(32) NOT NULL,
    file_size_bytes BIGINT,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(scan_id, file_path)
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
    exploitability VARCHAR(32) DEFAULT 'likely',
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
    remediation_resources JSONB,
    -- Deduplication fields
    canonical_id VARCHAR(256),
    tool_sources JSONB DEFAULT '[]',
    affected_resources JSONB DEFAULT '[]',
    -- Phase 1: Enhanced scoring fields
    asset_criticality VARCHAR(16) DEFAULT 'medium',
    blast_radius INTEGER DEFAULT 1,
    recurrence_count INTEGER DEFAULT 1,
    scoring_factors JSONB DEFAULT '{}',
    -- Phase 1: Threat intelligence fields
    threat_intel_enrichment JSONB DEFAULT NULL,
    threat_intel_last_checked TIMESTAMP
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

-- Scan files indexes
CREATE INDEX IF NOT EXISTS idx_scan_files_scan_id ON scan_files(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_files_tool ON scan_files(tool);

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
-- Optimized Indexes (Added for Query Performance)
-- ============================================================================
-- These indexes are designed based on API query patterns and common usage

-- -----------------------------------------------------------------------------
-- Foreign Key Indexes
-- -----------------------------------------------------------------------------
-- Foreign keys should have indexes to speed up JOIN operations and CASCADE deletes

-- compliance_mappings.finding_id FK (referenced in compliance_coverage view)
CREATE INDEX IF NOT EXISTS idx_compliance_mappings_finding_id ON compliance_mappings(finding_id);

-- -----------------------------------------------------------------------------
-- Composite Indexes for Multi-Column Filters
-- -----------------------------------------------------------------------------
-- These optimize queries that filter on multiple columns together

-- Findings: status + severity (very common filter combination in API)
CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON findings(status, severity);

-- Findings: status + cloud_provider (used in summary and export queries)
CREATE INDEX IF NOT EXISTS idx_findings_status_provider ON findings(status, cloud_provider);

-- Findings: status + tool (used in summary queries)
CREATE INDEX IF NOT EXISTS idx_findings_status_tool ON findings(status, tool);

-- Findings: scan_date DESC + severity (for pagination ORDER BY)
CREATE INDEX IF NOT EXISTS idx_findings_scandate_severity ON findings(scan_date DESC, severity);

-- Findings: severity + scan_date DESC (for export ORDER BY)
CREATE INDEX IF NOT EXISTS idx_findings_severity_scandate ON findings(severity, scan_date DESC);

-- Scans: status + started_at DESC (list_scans pagination)
CREATE INDEX IF NOT EXISTS idx_scans_status_started ON scans(status, started_at DESC);

-- Attack paths: risk_score + created_at (for pagination ORDER BY)
CREATE INDEX IF NOT EXISTS idx_attack_paths_risk_created ON attack_paths(risk_score DESC, created_at DESC);

-- Assets: cloud_provider + asset_type (common filter combination)
CREATE INDEX IF NOT EXISTS idx_assets_provider_type ON assets(cloud_provider, asset_type);

-- Assets: is_active + cloud_provider (for active asset queries)
CREATE INDEX IF NOT EXISTS idx_assets_active_provider ON assets(is_active, cloud_provider) WHERE is_active = true;

-- K8s: cluster_name + namespace + resource_type (common K8s query pattern)
CREATE INDEX IF NOT EXISTS idx_k8s_cluster_ns_type ON k8s_resources(cluster_name, namespace, resource_type);

-- -----------------------------------------------------------------------------
-- Partial Indexes for Status Filters
-- -----------------------------------------------------------------------------
-- These are smaller indexes that only include active/open records

-- Open findings only (most queries default to open/fail status)
CREATE INDEX IF NOT EXISTS idx_findings_open ON findings(severity, cloud_provider, tool)
    WHERE status IN ('open', 'fail');

-- Open findings by scan_date (for recent findings queries)
CREATE INDEX IF NOT EXISTS idx_findings_open_recent ON findings(scan_date DESC)
    WHERE status IN ('open', 'fail');

-- Open findings by resource_type (for top_vulnerable_resources view)
CREATE INDEX IF NOT EXISTS idx_findings_open_resource ON findings(resource_type, cloud_provider)
    WHERE status = 'open';

-- Running scans only
CREATE INDEX IF NOT EXISTS idx_scans_running ON scans(started_at DESC)
    WHERE status IN ('running', 'pending');

-- Critical/High risk attack paths
CREATE INDEX IF NOT EXISTS idx_attack_paths_critical ON attack_paths(risk_score DESC, created_at DESC)
    WHERE risk_score >= 60;

-- Active assets only
CREATE INDEX IF NOT EXISTS idx_assets_active ON assets(cloud_provider, asset_type, security_findings_count)
    WHERE is_active = true;

-- -----------------------------------------------------------------------------
-- Additional Single-Column Indexes
-- -----------------------------------------------------------------------------
-- Columns frequently used in WHERE clauses that weren't indexed

-- Findings: resource_id (for /by-resource/{resource_id} endpoint)
CREATE INDEX IF NOT EXISTS idx_findings_resource_id ON findings(resource_id);

-- Findings: account_id (for filtering by AWS/GCP account)
CREATE INDEX IF NOT EXISTS idx_findings_account_id ON findings(account_id);

-- Findings: region (for regional filtering)
CREATE INDEX IF NOT EXISTS idx_findings_region ON findings(region);

-- Findings: first_seen (for temporal analysis)
CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON findings(first_seen);

-- Findings: last_seen (for tracking recurrence)
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);

-- Findings: cve_id (for CVE lookups)
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id) WHERE cve_id IS NOT NULL;

-- Scans: tool (used in list_scans filter)
CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool);

-- Scans: completed_at (for completed scan queries)
CREATE INDEX IF NOT EXISTS idx_scans_completed ON scans(completed_at DESC) WHERE completed_at IS NOT NULL;

-- Container images: image_name (for image lookups)
CREATE INDEX IF NOT EXISTS idx_images_name ON container_images(image_name);

-- Container images: last_scanned (for scan recency)
CREATE INDEX IF NOT EXISTS idx_images_scanned ON container_images(last_scanned DESC);

-- -----------------------------------------------------------------------------
-- JSONB Indexes for Metadata Queries
-- -----------------------------------------------------------------------------
-- GIN indexes for JSONB columns enable fast key/value lookups

-- Findings: tags (for tag-based filtering)
CREATE INDEX IF NOT EXISTS idx_findings_tags ON findings USING GIN (tags);

-- Findings: compliance_frameworks (for compliance queries)
CREATE INDEX IF NOT EXISTS idx_findings_compliance ON findings USING GIN (compliance_frameworks);

-- Assets: tags (for tag-based filtering)
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN (tags);

-- K8s resources: labels (for label selectors)
CREATE INDEX IF NOT EXISTS idx_k8s_labels ON k8s_resources USING GIN (labels);

-- -----------------------------------------------------------------------------
-- Text Search Index for Title Searches
-- -----------------------------------------------------------------------------
-- GIN trigram index for fast ILIKE pattern matching on finding titles

-- Enable pg_trgm extension for trigram indexes (faster ILIKE searches)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Trigram index on finding titles for fast text search
CREATE INDEX IF NOT EXISTS idx_findings_title_trgm ON findings USING GIN (title gin_trgm_ops);

-- -----------------------------------------------------------------------------
-- Compliance Mappings Composite Indexes
-- -----------------------------------------------------------------------------
-- Optimize compliance_coverage view and framework queries

-- Framework + control_id (common lookup pattern)
CREATE INDEX IF NOT EXISTS idx_compliance_framework_control ON compliance_mappings(framework, control_id);

-- Framework + finding_id (for joining with findings)
CREATE INDEX IF NOT EXISTS idx_compliance_framework_finding ON compliance_mappings(framework, finding_id);

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
    -- CVSS-style severity scoring columns
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='exploitability') THEN
        ALTER TABLE findings ADD COLUMN exploitability VARCHAR(32) DEFAULT 'likely';
    END IF;
END $$;

-- Create index for canonical_id if not exists
CREATE INDEX IF NOT EXISTS idx_findings_canonical ON findings(canonical_id);

-- ============================================================================
-- Pentest Feature Tables
-- ============================================================================

-- 1. Public Exposure Aggregator - Consolidated view of public-facing resources
CREATE TABLE IF NOT EXISTS public_exposures (
    id SERIAL PRIMARY KEY,
    exposure_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    cloud_provider VARCHAR(32) NOT NULL,
    account_id VARCHAR(128),
    region VARCHAR(64),
    resource_type VARCHAR(128) NOT NULL,
    resource_id VARCHAR(512),
    resource_name VARCHAR(512),
    exposure_type VARCHAR(64) NOT NULL,
    exposure_details JSONB,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'medium',
    protocol VARCHAR(32),
    port_range VARCHAR(64),
    source_cidr VARCHAR(64),
    is_internet_exposed BOOLEAN DEFAULT FALSE,
    finding_ids INTEGER[],
    tags JSONB,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    status VARCHAR(32) DEFAULT 'open',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 2. Credential Harvesting Dashboard - Aggregated exposed credentials
CREATE TABLE IF NOT EXISTS exposed_credentials (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    cloud_provider VARCHAR(32) NOT NULL,
    account_id VARCHAR(128),
    region VARCHAR(64),
    source_type VARCHAR(64) NOT NULL,
    source_location VARCHAR(512),
    credential_type VARCHAR(64) NOT NULL,
    credential_name VARCHAR(256),
    exposed_value_hash VARCHAR(128),
    is_active BOOLEAN DEFAULT TRUE,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'critical',
    finding_ids INTEGER[],
    discovered_by VARCHAR(64),
    remediation_status VARCHAR(32) DEFAULT 'pending',
    remediation_notes TEXT,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 3. Finding Severity Override - User overrides on finding severity
CREATE TABLE IF NOT EXISTS severity_overrides (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    original_severity VARCHAR(16) NOT NULL,
    new_severity VARCHAR(16) NOT NULL,
    justification TEXT NOT NULL,
    override_type VARCHAR(32) DEFAULT 'manual',
    created_by VARCHAR(128),
    approved_by VARCHAR(128),
    approval_status VARCHAR(32) DEFAULT 'pending',
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(finding_id)
);

-- 4. Privilege Escalation Path Finder - IAM privesc chains
CREATE TABLE IF NOT EXISTS privesc_paths (
    id SERIAL PRIMARY KEY,
    path_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    cloud_provider VARCHAR(32) NOT NULL,
    account_id VARCHAR(128),
    source_principal_type VARCHAR(64) NOT NULL,
    source_principal_arn VARCHAR(512),
    source_principal_name VARCHAR(256),
    target_principal_type VARCHAR(64) NOT NULL,
    target_principal_arn VARCHAR(512),
    target_principal_name VARCHAR(256),
    escalation_method VARCHAR(128) NOT NULL,
    escalation_details JSONB,
    path_nodes JSONB NOT NULL,
    path_edges JSONB NOT NULL,
    risk_score INTEGER DEFAULT 0,
    exploitability VARCHAR(32) DEFAULT 'theoretical',
    requires_conditions JSONB,
    mitre_techniques TEXT[],
    poc_commands JSONB,
    finding_ids INTEGER[],
    status VARCHAR(32) DEFAULT 'open',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 5. IMDS/Metadata Checker - Instance metadata vulnerability checks
CREATE TABLE IF NOT EXISTS imds_checks (
    id SERIAL PRIMARY KEY,
    check_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    cloud_provider VARCHAR(32) NOT NULL,
    account_id VARCHAR(128),
    region VARCHAR(64),
    instance_id VARCHAR(128),
    instance_name VARCHAR(256),
    imds_version VARCHAR(16),
    imds_v1_enabled BOOLEAN DEFAULT FALSE,
    imds_hop_limit INTEGER,
    http_endpoint_enabled BOOLEAN DEFAULT TRUE,
    http_tokens_required BOOLEAN DEFAULT FALSE,
    ssrf_vulnerable BOOLEAN DEFAULT FALSE,
    container_credential_exposure BOOLEAN DEFAULT FALSE,
    ecs_task_role_exposed BOOLEAN DEFAULT FALSE,
    eks_pod_identity_exposed BOOLEAN DEFAULT FALSE,
    vulnerability_details JSONB,
    risk_level VARCHAR(16) DEFAULT 'medium',
    finding_ids INTEGER[],
    remediation_status VARCHAR(32) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 6. CloudFox Integration - CloudFox enumeration results
CREATE TABLE IF NOT EXISTS cloudfox_results (
    id SERIAL PRIMARY KEY,
    result_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    cloud_provider VARCHAR(32) NOT NULL,
    account_id VARCHAR(128),
    region VARCHAR(64),
    module_name VARCHAR(64) NOT NULL,
    result_type VARCHAR(64),
    resource_arn VARCHAR(512),
    resource_name VARCHAR(256),
    finding_category VARCHAR(64),
    finding_details JSONB,
    risk_level VARCHAR(16) DEFAULT 'medium',
    loot_file_path VARCHAR(512),
    raw_output TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 7. Pacu Integration - Pacu module execution results
CREATE TABLE IF NOT EXISTS pacu_results (
    id SERIAL PRIMARY KEY,
    result_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    session_name VARCHAR(128),
    module_name VARCHAR(128) NOT NULL,
    module_category VARCHAR(64),
    execution_status VARCHAR(32),
    target_account_id VARCHAR(128),
    target_region VARCHAR(64),
    resources_affected INTEGER DEFAULT 0,
    permissions_used JSONB,
    findings JSONB,
    loot_data JSONB,
    error_message TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 8. enumerate-iam Integration - IAM permission enumeration results
CREATE TABLE IF NOT EXISTS enumerate_iam_results (
    id SERIAL PRIMARY KEY,
    result_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    account_id VARCHAR(128),
    principal_arn VARCHAR(512),
    principal_name VARCHAR(256),
    principal_type VARCHAR(64),
    enumeration_method VARCHAR(64),
    confirmed_permissions JSONB,
    denied_permissions JSONB,
    error_permissions JSONB,
    permission_count INTEGER DEFAULT 0,
    high_risk_permissions JSONB,
    privesc_capable BOOLEAN DEFAULT FALSE,
    data_access_capable BOOLEAN DEFAULT FALSE,
    admin_capable BOOLEAN DEFAULT FALSE,
    enumeration_duration_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 9. Assumed Role Mapper - Role assumption relationships (Neo4j augmentation)
CREATE TABLE IF NOT EXISTS assumed_role_mappings (
    id SERIAL PRIMARY KEY,
    mapping_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    cloud_provider VARCHAR(32) NOT NULL,
    account_id VARCHAR(128),
    source_principal_type VARCHAR(64) NOT NULL,
    source_principal_arn VARCHAR(512),
    source_principal_name VARCHAR(256),
    source_account_id VARCHAR(128),
    target_role_arn VARCHAR(512) NOT NULL,
    target_role_name VARCHAR(256),
    target_account_id VARCHAR(128),
    trust_policy JSONB,
    conditions JSONB,
    is_cross_account BOOLEAN DEFAULT FALSE,
    is_external_id_required BOOLEAN DEFAULT FALSE,
    external_id_value VARCHAR(256),
    max_session_duration INTEGER,
    assumption_chain_depth INTEGER DEFAULT 1,
    risk_level VARCHAR(16) DEFAULT 'medium',
    neo4j_synced BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 10. Lambda Code Analysis - Serverless function code analysis results
CREATE TABLE IF NOT EXISTS lambda_analysis (
    id SERIAL PRIMARY KEY,
    analysis_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    cloud_provider VARCHAR(32) NOT NULL DEFAULT 'aws',
    account_id VARCHAR(128),
    region VARCHAR(64),
    function_arn VARCHAR(512),
    function_name VARCHAR(256),
    runtime VARCHAR(64),
    handler VARCHAR(256),
    code_size_bytes BIGINT,
    memory_size INTEGER,
    timeout_seconds INTEGER,
    environment_variables JSONB,
    has_vpc_config BOOLEAN DEFAULT FALSE,
    layers JSONB,
    secrets_found JSONB,
    hardcoded_credentials JSONB,
    vulnerable_dependencies JSONB,
    insecure_patterns JSONB,
    api_keys_exposed JSONB,
    database_connections JSONB,
    external_urls JSONB,
    risk_score INTEGER DEFAULT 0,
    risk_level VARCHAR(16) DEFAULT 'medium',
    finding_ids INTEGER[],
    analysis_status VARCHAR(32) DEFAULT 'pending',
    analysis_error TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ============================================================================
-- Indexes for Pentest Feature Tables
-- ============================================================================

-- Public exposures indexes
CREATE INDEX IF NOT EXISTS idx_public_exposures_provider ON public_exposures(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_public_exposures_type ON public_exposures(exposure_type);
CREATE INDEX IF NOT EXISTS idx_public_exposures_risk ON public_exposures(risk_level);
CREATE INDEX IF NOT EXISTS idx_public_exposures_status ON public_exposures(status);

-- Exposed credentials indexes
CREATE INDEX IF NOT EXISTS idx_exposed_credentials_provider ON exposed_credentials(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_exposed_credentials_type ON exposed_credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_exposed_credentials_source ON exposed_credentials(source_type);
CREATE INDEX IF NOT EXISTS idx_exposed_credentials_risk ON exposed_credentials(risk_level);

-- Severity overrides indexes
CREATE INDEX IF NOT EXISTS idx_severity_overrides_finding ON severity_overrides(finding_id);
CREATE INDEX IF NOT EXISTS idx_severity_overrides_status ON severity_overrides(approval_status);

-- Privesc paths indexes
CREATE INDEX IF NOT EXISTS idx_privesc_paths_provider ON privesc_paths(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_privesc_paths_method ON privesc_paths(escalation_method);
CREATE INDEX IF NOT EXISTS idx_privesc_paths_risk ON privesc_paths(risk_score DESC);

-- IMDS checks indexes
CREATE INDEX IF NOT EXISTS idx_imds_checks_provider ON imds_checks(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_imds_checks_instance ON imds_checks(instance_id);
CREATE INDEX IF NOT EXISTS idx_imds_checks_v1 ON imds_checks(imds_v1_enabled);

-- CloudFox results indexes
CREATE INDEX IF NOT EXISTS idx_cloudfox_provider ON cloudfox_results(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_cloudfox_module ON cloudfox_results(module_name);
CREATE INDEX IF NOT EXISTS idx_cloudfox_category ON cloudfox_results(finding_category);

-- Pacu results indexes
CREATE INDEX IF NOT EXISTS idx_pacu_module ON pacu_results(module_name);
CREATE INDEX IF NOT EXISTS idx_pacu_category ON pacu_results(module_category);
CREATE INDEX IF NOT EXISTS idx_pacu_status ON pacu_results(execution_status);

-- enumerate-iam results indexes
CREATE INDEX IF NOT EXISTS idx_enum_iam_principal ON enumerate_iam_results(principal_arn);
CREATE INDEX IF NOT EXISTS idx_enum_iam_privesc ON enumerate_iam_results(privesc_capable);
CREATE INDEX IF NOT EXISTS idx_enum_iam_admin ON enumerate_iam_results(admin_capable);

-- Assumed role mappings indexes
CREATE INDEX IF NOT EXISTS idx_assumed_role_source ON assumed_role_mappings(source_principal_arn);
CREATE INDEX IF NOT EXISTS idx_assumed_role_target ON assumed_role_mappings(target_role_arn);
CREATE INDEX IF NOT EXISTS idx_assumed_role_cross ON assumed_role_mappings(is_cross_account);

-- Lambda analysis indexes
CREATE INDEX IF NOT EXISTS idx_lambda_function ON lambda_analysis(function_arn);
CREATE INDEX IF NOT EXISTS idx_lambda_risk ON lambda_analysis(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_lambda_status ON lambda_analysis(analysis_status);

-- ============================================================================
-- Triggers for Pentest Feature Tables
-- ============================================================================

DROP TRIGGER IF EXISTS update_public_exposures_updated_at ON public_exposures;
CREATE TRIGGER update_public_exposures_updated_at BEFORE UPDATE ON public_exposures
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_exposed_credentials_updated_at ON exposed_credentials;
CREATE TRIGGER update_exposed_credentials_updated_at BEFORE UPDATE ON exposed_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_severity_overrides_updated_at ON severity_overrides;
CREATE TRIGGER update_severity_overrides_updated_at BEFORE UPDATE ON severity_overrides
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_privesc_paths_updated_at ON privesc_paths;
CREATE TRIGGER update_privesc_paths_updated_at BEFORE UPDATE ON privesc_paths
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_imds_checks_updated_at ON imds_checks;
CREATE TRIGGER update_imds_checks_updated_at BEFORE UPDATE ON imds_checks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_cloudfox_results_updated_at ON cloudfox_results;
CREATE TRIGGER update_cloudfox_results_updated_at BEFORE UPDATE ON cloudfox_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_pacu_results_updated_at ON pacu_results;
CREATE TRIGGER update_pacu_results_updated_at BEFORE UPDATE ON pacu_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_enumerate_iam_results_updated_at ON enumerate_iam_results;
CREATE TRIGGER update_enumerate_iam_results_updated_at BEFORE UPDATE ON enumerate_iam_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_assumed_role_mappings_updated_at ON assumed_role_mappings;
CREATE TRIGGER update_assumed_role_mappings_updated_at BEFORE UPDATE ON assumed_role_mappings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_lambda_analysis_updated_at ON lambda_analysis;
CREATE TRIGGER update_lambda_analysis_updated_at BEFORE UPDATE ON lambda_analysis
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Views for Pentest Features
-- ============================================================================

-- Public exposure summary view
CREATE OR REPLACE VIEW public_exposure_summary AS
SELECT
    cloud_provider,
    exposure_type,
    risk_level,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE is_internet_exposed = true) as internet_exposed_count
FROM public_exposures
WHERE status = 'open'
GROUP BY cloud_provider, exposure_type, risk_level
ORDER BY
    CASE risk_level
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END;

-- Credential exposure summary view
CREATE OR REPLACE VIEW credential_exposure_summary AS
SELECT
    cloud_provider,
    credential_type,
    source_type,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE is_active = true) as active_count
FROM exposed_credentials
WHERE remediation_status != 'resolved'
GROUP BY cloud_provider, credential_type, source_type
ORDER BY count DESC;

-- High-risk privesc paths view
CREATE OR REPLACE VIEW high_risk_privesc_paths AS
SELECT
    id,
    path_id,
    cloud_provider,
    source_principal_name,
    target_principal_name,
    escalation_method,
    risk_score,
    exploitability
FROM privesc_paths
WHERE risk_score >= 70
ORDER BY risk_score DESC;

-- Lambda security issues view
CREATE OR REPLACE VIEW lambda_security_issues AS
SELECT
    function_arn,
    function_name,
    region,
    risk_score,
    risk_level,
    jsonb_array_length(COALESCE(secrets_found, '[]'::jsonb)) as secrets_count,
    jsonb_array_length(COALESCE(hardcoded_credentials, '[]'::jsonb)) as hardcoded_creds_count,
    jsonb_array_length(COALESCE(vulnerable_dependencies, '[]'::jsonb)) as vuln_deps_count
FROM lambda_analysis
WHERE risk_score > 0
ORDER BY risk_score DESC;

-- ============================================================================
-- Tool Execution Tracking
-- ============================================================================

-- Tool executions table - tracks async tool runs (CloudFox, Pacu, enumerate-iam, etc.)
CREATE TABLE IF NOT EXISTS tool_executions (
    id SERIAL PRIMARY KEY,
    execution_id VARCHAR(64) UNIQUE NOT NULL,
    tool_name VARCHAR(64) NOT NULL,
    tool_type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    container_id VARCHAR(128),
    config JSONB NOT NULL DEFAULT '{}',
    output_path VARCHAR(512),
    error_message TEXT,
    exit_code INTEGER,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Tool execution indexes
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_executions_status ON tool_executions(status);
CREATE INDEX IF NOT EXISTS idx_tool_executions_created ON tool_executions(created_at DESC);

-- Tool execution trigger
DROP TRIGGER IF EXISTS update_tool_executions_updated_at ON tool_executions;
CREATE TRIGGER update_tool_executions_updated_at BEFORE UPDATE ON tool_executions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- User Settings (Configuration & Preferences)
-- ============================================================================

-- User settings table - stores application configuration and user preferences
CREATE TABLE IF NOT EXISTS user_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(128) UNIQUE NOT NULL,
    setting_value JSONB NOT NULL,
    category VARCHAR(64) NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- User settings index
CREATE INDEX IF NOT EXISTS idx_user_settings_category ON user_settings(category);
CREATE INDEX IF NOT EXISTS idx_user_settings_key ON user_settings(setting_key);

-- User settings trigger
DROP TRIGGER IF EXISTS update_user_settings_updated_at ON user_settings;
CREATE TRIGGER update_user_settings_updated_at BEFORE UPDATE ON user_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Default user settings
INSERT INTO user_settings (setting_key, setting_value, category, description) VALUES
    ('default_scan_profile', '"quick"', 'scans', 'Default scan profile to use when starting new scans'),
    ('default_regions', '["us-east-1", "us-west-2", "eu-west-1"]', 'scans', 'Default AWS regions to scan'),
    ('default_severity_filter', '["critical", "high"]', 'scans', 'Default severity levels to include in scans'),
    ('auto_cleanup_days', '90', 'data', 'Number of days to retain scan data before automatic cleanup'),
    ('export_format', '"json"', 'data', 'Default export format for findings and reports'),
    ('max_concurrent_scans', '3', 'scans', 'Maximum number of scans that can run concurrently'),
    ('notifications_enabled', 'false', 'notifications', 'Enable or disable all notifications'),
    ('webhook_url', 'null', 'notifications', 'Webhook URL for scan completion notifications'),
    ('webhook_events', '["scan_completed", "critical_finding"]', 'notifications', 'Events that trigger webhook notifications'),
    ('email_alerts_enabled', 'false', 'notifications', 'Enable email alerts for critical findings'),
    ('email_recipients', '[]', 'notifications', 'Email addresses to receive alert notifications'),
    ('slack_webhook_url', 'null', 'notifications', 'Slack webhook URL for notifications'),
    ('theme', '"system"', 'display', 'UI theme preference (light, dark, system)'),
    ('findings_per_page', '50', 'display', 'Number of findings to display per page'),
    ('auto_refresh_interval', '30', 'display', 'Dashboard auto-refresh interval in seconds')
ON CONFLICT (setting_key) DO NOTHING;

-- ============================================================================
-- Credential Status Cache
-- ============================================================================

-- Credential verification cache - stores last verification results for quick status display
CREATE TABLE IF NOT EXISTS credential_status_cache (
    id SERIAL PRIMARY KEY,
    provider VARCHAR(32) UNIQUE NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    identity VARCHAR(256),
    account_info VARCHAR(256),
    tools_ready JSONB DEFAULT '[]',
    tools_partial JSONB DEFAULT '[]',
    tools_failed JSONB DEFAULT '[]',
    last_verified TIMESTAMP,
    verification_error TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Credential status cache index
CREATE INDEX IF NOT EXISTS idx_credential_status_provider ON credential_status_cache(provider);

-- Credential status cache trigger
DROP TRIGGER IF EXISTS update_credential_status_cache_updated_at ON credential_status_cache;
CREATE TRIGGER update_credential_status_cache_updated_at BEFORE UPDATE ON credential_status_cache
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Initialize credential status for all providers
INSERT INTO credential_status_cache (provider, status) VALUES
    ('aws', 'unknown'),
    ('azure', 'unknown'),
    ('gcp', 'unknown'),
    ('kubernetes', 'unknown')
ON CONFLICT (provider) DO NOTHING;

-- ============================================================================
-- Attack Path Validation Features (v2)
-- ============================================================================

-- Extend attack_paths table with validation columns
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='validation_status') THEN
        ALTER TABLE attack_paths ADD COLUMN validation_status VARCHAR(32) DEFAULT 'pending';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='validation_timestamp') THEN
        ALTER TABLE attack_paths ADD COLUMN validation_timestamp TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='validation_evidence') THEN
        ALTER TABLE attack_paths ADD COLUMN validation_evidence JSONB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='validation_error') THEN
        ALTER TABLE attack_paths ADD COLUMN validation_error TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='runtime_confirmed') THEN
        ALTER TABLE attack_paths ADD COLUMN runtime_confirmed BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='cloudtrail_events') THEN
        ALTER TABLE attack_paths ADD COLUMN cloudtrail_events JSONB DEFAULT '[]';
    END IF;
END $$;

-- Extend privesc_paths table with validation columns
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='privesc_paths' AND column_name='validation_status') THEN
        ALTER TABLE privesc_paths ADD COLUMN validation_status VARCHAR(32) DEFAULT 'pending';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='privesc_paths' AND column_name='validation_timestamp') THEN
        ALTER TABLE privesc_paths ADD COLUMN validation_timestamp TIMESTAMP;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='privesc_paths' AND column_name='validation_evidence') THEN
        ALTER TABLE privesc_paths ADD COLUMN validation_evidence JSONB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='privesc_paths' AND column_name='runtime_confirmed') THEN
        ALTER TABLE privesc_paths ADD COLUMN runtime_confirmed BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='privesc_paths' AND column_name='cloudtrail_events') THEN
        ALTER TABLE privesc_paths ADD COLUMN cloudtrail_events JSONB DEFAULT '[]';
    END IF;
END $$;

-- Indexes for validation status queries
CREATE INDEX IF NOT EXISTS idx_attack_paths_validation ON attack_paths(validation_status);
CREATE INDEX IF NOT EXISTS idx_attack_paths_runtime ON attack_paths(runtime_confirmed) WHERE runtime_confirmed = true;
CREATE INDEX IF NOT EXISTS idx_privesc_paths_validation ON privesc_paths(validation_status);
CREATE INDEX IF NOT EXISTS idx_privesc_paths_runtime ON privesc_paths(runtime_confirmed) WHERE runtime_confirmed = true;

-- Blast Radius Analysis Table
CREATE TABLE IF NOT EXISTS blast_radius_analyses (
    id SERIAL PRIMARY KEY,
    analysis_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    identity_arn VARCHAR(512) NOT NULL,
    identity_type VARCHAR(64),
    account_id VARCHAR(128),
    direct_permission_count INTEGER DEFAULT 0,
    direct_resource_count INTEGER DEFAULT 0,
    assumable_roles_count INTEGER DEFAULT 0,
    assumption_chain_depth INTEGER DEFAULT 1,
    cross_account_roles_count INTEGER DEFAULT 0,
    affected_accounts JSONB DEFAULT '[]',
    total_blast_radius INTEGER DEFAULT 0,
    risk_level VARCHAR(16) DEFAULT 'medium',
    reachable_resources JSONB,
    reachable_roles JSONB,
    permission_breakdown JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Blast radius indexes
CREATE INDEX IF NOT EXISTS idx_blast_radius_identity ON blast_radius_analyses(identity_arn);
CREATE INDEX IF NOT EXISTS idx_blast_radius_scan ON blast_radius_analyses(scan_id);
CREATE INDEX IF NOT EXISTS idx_blast_radius_risk ON blast_radius_analyses(risk_level, total_blast_radius DESC);
CREATE INDEX IF NOT EXISTS idx_blast_radius_account ON blast_radius_analyses(account_id);

-- Blast radius trigger
DROP TRIGGER IF EXISTS update_blast_radius_analyses_updated_at ON blast_radius_analyses;
CREATE TRIGGER update_blast_radius_analyses_updated_at BEFORE UPDATE ON blast_radius_analyses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Runtime Correlations Table
CREATE TABLE IF NOT EXISTS runtime_correlations (
    id SERIAL PRIMARY KEY,
    correlation_id VARCHAR(64) UNIQUE NOT NULL,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    attack_path_id INTEGER REFERENCES attack_paths(id) ON DELETE CASCADE,
    privesc_path_id INTEGER REFERENCES privesc_paths(id) ON DELETE CASCADE,
    event_id VARCHAR(128),
    event_source VARCHAR(128),
    event_name VARCHAR(128),
    event_time TIMESTAMP,
    source_ip VARCHAR(64),
    user_identity JSONB,
    request_parameters JSONB,
    response_elements JSONB,
    correlation_type VARCHAR(64),
    confidence_score INTEGER DEFAULT 0,
    analysis_notes TEXT,
    confirms_exploitability BOOLEAN DEFAULT FALSE,
    anomaly_detected BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Runtime correlation indexes
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_finding ON runtime_correlations(finding_id);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_attack_path ON runtime_correlations(attack_path_id);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_privesc ON runtime_correlations(privesc_path_id);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_type ON runtime_correlations(correlation_type);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_confirmed ON runtime_correlations(confirms_exploitability) WHERE confirms_exploitability = true;
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_anomaly ON runtime_correlations(anomaly_detected) WHERE anomaly_detected = true;
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_event_time ON runtime_correlations(event_time DESC);

-- New feature user settings
INSERT INTO user_settings (setting_key, setting_value, category, description) VALUES
    ('auto_validate_poc', 'false', 'scans', 'Automatically run PoC validation after attack path analysis'),
    ('cloudtrail_correlation', 'false', 'scans', 'Enable CloudTrail event correlation for findings'),
    ('blast_radius_auto_analyze', 'true', 'scans', 'Automatically calculate blast radius after identity enumeration'),
    ('poc_validation_timeout', '30', 'scans', 'Timeout in seconds for PoC validation commands'),
    ('cloudtrail_lookback_hours', '24', 'scans', 'Hours to look back for CloudTrail correlation')
ON CONFLICT (setting_key) DO NOTHING;

-- Grant permissions on new tables
GRANT ALL PRIVILEGES ON blast_radius_analyses TO auditor;
GRANT ALL PRIVILEGES ON runtime_correlations TO auditor;

-- ============================================================================
-- Tier 1 & 2 Enhancement Tables
-- ============================================================================

-- Risk Exceptions table (Tier 1: Compliance Exception Tracking)
CREATE TABLE IF NOT EXISTS risk_exceptions (
    id SERIAL PRIMARY KEY,
    exception_id VARCHAR(64) UNIQUE NOT NULL,
    canonical_id VARCHAR(256) NOT NULL,  -- Cross-scan persistence
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    justification TEXT NOT NULL,
    expiration_date TIMESTAMP,  -- Optional: null = permanent exception
    accepted_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(32) DEFAULT 'active',  -- active, expired, revoked
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Analysis Jobs table (Tier 2: Async Attack Path Analysis)
CREATE TABLE IF NOT EXISTS analysis_jobs (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(64) UNIQUE NOT NULL,
    job_type VARCHAR(32) NOT NULL,  -- attack_path, privesc, blast_radius
    scan_id UUID REFERENCES scans(scan_id) ON DELETE SET NULL,
    status VARCHAR(32) DEFAULT 'pending',  -- pending, running, completed, failed
    progress INTEGER DEFAULT 0,  -- 0-100 percent
    result_summary JSONB,
    error_message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Finding Validations table (Tier 1: PoC Validation for Findings)
CREATE TABLE IF NOT EXISTS finding_validations (
    id SERIAL PRIMARY KEY,
    validation_id VARCHAR(64) UNIQUE NOT NULL,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE NOT NULL,
    validation_status VARCHAR(32) DEFAULT 'pending',  -- pending, validated, blocked, failed
    validation_timestamp TIMESTAMP,
    evidence JSONB DEFAULT '[]',
    error_message TEXT,
    dry_run BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Add confidence scoring fields to attack_paths if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='confidence_score') THEN
        ALTER TABLE attack_paths ADD COLUMN confidence_score INTEGER DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='attack_paths' AND column_name='confidence_factors') THEN
        ALTER TABLE attack_paths ADD COLUMN confidence_factors JSONB DEFAULT '{}';
    END IF;
END $$;

-- ============================================================================
-- Tier 1 & 2 Indexes
-- ============================================================================

-- Risk exceptions indexes
CREATE INDEX IF NOT EXISTS idx_risk_exceptions_canonical ON risk_exceptions(canonical_id);
CREATE INDEX IF NOT EXISTS idx_risk_exceptions_status ON risk_exceptions(status);
CREATE INDEX IF NOT EXISTS idx_risk_exceptions_finding ON risk_exceptions(finding_id);
CREATE INDEX IF NOT EXISTS idx_risk_exceptions_expiration ON risk_exceptions(expiration_date) WHERE expiration_date IS NOT NULL;

-- Analysis jobs indexes
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status ON analysis_jobs(status);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_type ON analysis_jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_scan ON analysis_jobs(scan_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_created ON analysis_jobs(created_at DESC);

-- Finding validations indexes
CREATE INDEX IF NOT EXISTS idx_finding_validations_finding ON finding_validations(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_validations_status ON finding_validations(validation_status);

-- Tier 3: Additional optimized indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_findings_canonical_status ON findings(canonical_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_canonical_open ON findings(canonical_id, severity)
    WHERE status IN ('open', 'fail');

-- Attack paths confidence index
CREATE INDEX IF NOT EXISTS idx_attack_paths_confidence ON attack_paths(confidence_score DESC) WHERE confidence_score > 0;

-- ============================================================================
-- Tier 1 & 2 Triggers
-- ============================================================================

DROP TRIGGER IF EXISTS update_risk_exceptions_updated_at ON risk_exceptions;
CREATE TRIGGER update_risk_exceptions_updated_at BEFORE UPDATE ON risk_exceptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_analysis_jobs_updated_at ON analysis_jobs;
CREATE TRIGGER update_analysis_jobs_updated_at BEFORE UPDATE ON analysis_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions on new tables
GRANT ALL PRIVILEGES ON risk_exceptions TO auditor;
GRANT ALL PRIVILEGES ON analysis_jobs TO auditor;
GRANT ALL PRIVILEGES ON finding_validations TO auditor;

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
