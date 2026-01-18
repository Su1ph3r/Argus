-- ============================================================================
-- Nubicustos - Phase 1 Features Database Migration
-- ============================================================================
-- This migration adds support for:
-- 1. Intelligent Alert Prioritization (enhanced scoring columns)
-- 2. Threat Intel Enrichment (design placeholder columns)
-- 3. Scheduled Scanning (new table)
-- 4. Notifications (new settings)
--
-- All changes are non-breaking:
-- - Uses ALTER TABLE ... ADD COLUMN IF NOT EXISTS
-- - All new columns have sensible defaults
-- - Existing data continues to work unchanged
-- ============================================================================

-- Enable UUID extension (should already exist)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Feature 1: Intelligent Alert Prioritization
-- ============================================================================

-- New columns for enhanced scoring
ALTER TABLE findings ADD COLUMN IF NOT EXISTS asset_criticality VARCHAR(16) DEFAULT 'medium';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS blast_radius INTEGER DEFAULT 1;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS recurrence_count INTEGER DEFAULT 1;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS scoring_factors JSONB DEFAULT '{}';

-- Performance index for risk score queries
CREATE INDEX IF NOT EXISTS idx_findings_risk_score_desc ON findings(risk_score DESC NULLS LAST)
    WHERE status IN ('open', 'fail');

-- New settings for alert prioritization
INSERT INTO user_settings (setting_key, setting_value, category, description) VALUES
    ('alert_suppression_rules', '[]', 'notifications', 'Finding suppression rules'),
    ('asset_criticality_map', '{}', 'scans', 'Asset criticality mappings'),
    ('top_critical_count', '10', 'display', 'Top critical findings count')
ON CONFLICT (setting_key) DO NOTHING;

-- ============================================================================
-- Feature 2: Threat Intelligence Enrichment (Design)
-- ============================================================================

-- Columns for threat intel data (populated later when providers are integrated)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS threat_intel_enrichment JSONB DEFAULT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS threat_intel_last_checked TIMESTAMP;

-- Settings for threat intel providers
INSERT INTO user_settings (setting_key, setting_value, category, description) VALUES
    ('threat_intel_providers', '[]', 'scans', 'Enabled threat intelligence providers'),
    ('threat_intel_auto_enrich', 'false', 'scans', 'Automatically enrich findings with threat intel')
ON CONFLICT (setting_key) DO NOTHING;

-- ============================================================================
-- Feature 3: Scheduled Scanning
-- ============================================================================

-- Create scan_schedules table
CREATE TABLE IF NOT EXISTS scan_schedules (
    id SERIAL PRIMARY KEY,
    schedule_id UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    name VARCHAR(128) NOT NULL,
    description TEXT,
    profile VARCHAR(64) NOT NULL,
    provider VARCHAR(32),
    aws_profile VARCHAR(64),
    azure_credentials JSONB,
    schedule_type VARCHAR(32) NOT NULL DEFAULT 'cron',
    cron_expression VARCHAR(128),
    interval_minutes INTEGER,
    next_run_at TIMESTAMP,
    last_run_at TIMESTAMP,
    last_run_status VARCHAR(32),
    last_scan_id UUID REFERENCES scans(scan_id) ON DELETE SET NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    run_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for scan_schedules
CREATE INDEX IF NOT EXISTS idx_scan_schedules_enabled ON scan_schedules(is_enabled) WHERE is_enabled = true;
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run ON scan_schedules(next_run_at) WHERE is_enabled = true;
CREATE INDEX IF NOT EXISTS idx_scan_schedules_profile ON scan_schedules(profile);

-- Trigger for updated_at on scan_schedules
DROP TRIGGER IF EXISTS update_scan_schedules_updated_at ON scan_schedules;
CREATE TRIGGER update_scan_schedules_updated_at BEFORE UPDATE ON scan_schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Feature 4: Notifications
-- ============================================================================

-- Add Teams webhook setting
INSERT INTO user_settings (setting_key, setting_value, category, description) VALUES
    ('teams_webhook_url', 'null', 'notifications', 'Microsoft Teams webhook URL for notifications')
ON CONFLICT (setting_key) DO NOTHING;

-- ============================================================================
-- Maintenance
-- ============================================================================

-- Vacuum and analyze for optimal performance
VACUUM ANALYZE findings;
VACUUM ANALYZE user_settings;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'Phase 1 migration completed successfully';
END $$;
