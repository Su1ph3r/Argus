-- ============================================================================
-- Nubicustos - Attack Path Validation Migration
-- Version: 2.0
-- Features: PoC Validation, Blast Radius Analysis, Runtime Correlation
-- ============================================================================

-- ============================================================================
-- Feature 1: PoC Validation Extensions
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
    -- Runtime correlation columns for attack_paths
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
    -- Runtime correlation columns for privesc_paths
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

-- ============================================================================
-- Feature 2: Blast Radius Analysis
-- ============================================================================

CREATE TABLE IF NOT EXISTS blast_radius_analyses (
    id SERIAL PRIMARY KEY,
    analysis_id VARCHAR(64) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    identity_arn VARCHAR(512) NOT NULL,
    identity_type VARCHAR(64),
    account_id VARCHAR(128),

    -- Direct permissions
    direct_permission_count INTEGER DEFAULT 0,
    direct_resource_count INTEGER DEFAULT 0,

    -- Role assumption analysis
    assumable_roles_count INTEGER DEFAULT 0,
    assumption_chain_depth INTEGER DEFAULT 1,
    cross_account_roles_count INTEGER DEFAULT 0,
    affected_accounts JSONB DEFAULT '[]',

    -- Calculated blast radius
    total_blast_radius INTEGER DEFAULT 0,
    risk_level VARCHAR(16) DEFAULT 'medium',

    -- Detailed breakdown
    reachable_resources JSONB,
    reachable_roles JSONB,
    permission_breakdown JSONB,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for blast radius queries
CREATE INDEX IF NOT EXISTS idx_blast_radius_identity ON blast_radius_analyses(identity_arn);
CREATE INDEX IF NOT EXISTS idx_blast_radius_scan ON blast_radius_analyses(scan_id);
CREATE INDEX IF NOT EXISTS idx_blast_radius_risk ON blast_radius_analyses(risk_level, total_blast_radius DESC);
CREATE INDEX IF NOT EXISTS idx_blast_radius_account ON blast_radius_analyses(account_id);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_blast_radius_analyses_updated_at ON blast_radius_analyses;
CREATE TRIGGER update_blast_radius_analyses_updated_at BEFORE UPDATE ON blast_radius_analyses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Feature 3: Runtime Correlation
-- ============================================================================

CREATE TABLE IF NOT EXISTS runtime_correlations (
    id SERIAL PRIMARY KEY,
    correlation_id VARCHAR(64) UNIQUE NOT NULL,

    -- Reference to findings/paths (one will be set)
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    attack_path_id INTEGER REFERENCES attack_paths(id) ON DELETE CASCADE,
    privesc_path_id INTEGER REFERENCES privesc_paths(id) ON DELETE CASCADE,

    -- CloudTrail event details
    event_id VARCHAR(128),
    event_source VARCHAR(128),
    event_name VARCHAR(128),
    event_time TIMESTAMP,
    source_ip VARCHAR(64),
    user_identity JSONB,
    request_parameters JSONB,
    response_elements JSONB,

    -- Correlation analysis
    correlation_type VARCHAR(64),
    confidence_score INTEGER DEFAULT 0,
    analysis_notes TEXT,
    confirms_exploitability BOOLEAN DEFAULT FALSE,
    anomaly_detected BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for runtime correlation queries
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_finding ON runtime_correlations(finding_id);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_attack_path ON runtime_correlations(attack_path_id);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_privesc ON runtime_correlations(privesc_path_id);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_type ON runtime_correlations(correlation_type);
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_confirmed ON runtime_correlations(confirms_exploitability) WHERE confirms_exploitability = true;
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_anomaly ON runtime_correlations(anomaly_detected) WHERE anomaly_detected = true;
CREATE INDEX IF NOT EXISTS idx_runtime_correlation_event_time ON runtime_correlations(event_time DESC);

-- ============================================================================
-- User Settings Extension
-- ============================================================================

-- Add new settings for the features
INSERT INTO user_settings (setting_key, setting_value, category, description) VALUES
    ('auto_validate_poc', 'false', 'scans', 'Automatically run PoC validation after attack path analysis'),
    ('cloudtrail_correlation', 'false', 'scans', 'Enable CloudTrail event correlation for findings'),
    ('blast_radius_auto_analyze', 'true', 'scans', 'Automatically calculate blast radius after identity enumeration'),
    ('poc_validation_timeout', '30', 'scans', 'Timeout in seconds for PoC validation commands'),
    ('cloudtrail_lookback_hours', '24', 'scans', 'Hours to look back for CloudTrail correlation')
ON CONFLICT (setting_key) DO NOTHING;

-- ============================================================================
-- Views for New Features
-- ============================================================================

-- High-impact identities by blast radius
CREATE OR REPLACE VIEW high_impact_identities AS
SELECT
    identity_arn,
    identity_type,
    account_id,
    total_blast_radius,
    risk_level,
    assumable_roles_count,
    cross_account_roles_count,
    assumption_chain_depth
FROM blast_radius_analyses
WHERE risk_level IN ('critical', 'high')
ORDER BY total_blast_radius DESC
LIMIT 50;

-- Runtime-confirmed vulnerabilities
CREATE OR REPLACE VIEW runtime_confirmed_vulnerabilities AS
SELECT
    rc.id as correlation_id,
    rc.correlation_type,
    rc.event_name,
    rc.event_time,
    rc.source_ip,
    rc.confidence_score,
    f.id as finding_id,
    f.title as finding_title,
    f.severity as finding_severity,
    ap.id as attack_path_id,
    ap.name as attack_path_name,
    pp.id as privesc_path_id,
    pp.source_principal_name as privesc_source
FROM runtime_correlations rc
LEFT JOIN findings f ON rc.finding_id = f.id
LEFT JOIN attack_paths ap ON rc.attack_path_id = ap.id
LEFT JOIN privesc_paths pp ON rc.privesc_path_id = pp.id
WHERE rc.confirms_exploitability = true
ORDER BY rc.event_time DESC;

-- Validation status summary
CREATE OR REPLACE VIEW validation_status_summary AS
SELECT
    'attack_paths' as path_type,
    validation_status,
    COUNT(*) as count
FROM attack_paths
GROUP BY validation_status
UNION ALL
SELECT
    'privesc_paths' as path_type,
    validation_status,
    COUNT(*) as count
FROM privesc_paths
GROUP BY validation_status;

-- ============================================================================
-- Maintenance
-- ============================================================================

-- Grant permissions
GRANT ALL PRIVILEGES ON blast_radius_analyses TO auditor;
GRANT ALL PRIVILEGES ON runtime_correlations TO auditor;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO auditor;

-- Vacuum and analyze new tables
VACUUM ANALYZE blast_radius_analyses;
VACUUM ANALYZE runtime_correlations;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'Attack validation migration completed successfully';
END $$;
