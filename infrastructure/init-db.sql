-- Aegentra Database Schema
-- Automatically executed when PostgreSQL container starts

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(100) UNIQUE NOT NULL,
    severity VARCHAR(20),
    status VARCHAR(50),
    source_ips TEXT[],
    destination_ips TEXT[],
    attack_type VARCHAR(100),
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id VARCHAR(100) REFERENCES incidents(incident_id),
    alert_type VARCHAR(50),
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    signature VARCHAR(500),
    severity INTEGER,
    raw_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs table (immutable)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    agent_name VARCHAR(100) NOT NULL,
    incident_id VARCHAR(100),
    action_type VARCHAR(50) NOT NULL,
    evidence JSONB,
    policy_rule VARCHAR(200),
    reasoning_trace TEXT,
    confidence_score FLOAT,
    action_outcome VARCHAR(50),
    metadata JSONB
);

-- Policy rules table
CREATE TABLE IF NOT EXISTS policy_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(200) UNIQUE NOT NULL,
    rule_type VARCHAR(50),
    conditions JSONB,
    actions TEXT[],
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_incidents_created_at ON incidents(created_at);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_alerts_incident_id ON alerts(incident_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_incident_id ON audit_logs(incident_id);

-- Insert default policy rules
INSERT INTO policy_rules (rule_name, rule_type, conditions, actions, priority) VALUES
('high_confidence_blocking', 'execution', '{"min_confidence": 0.85, "max_risk_score": 8}', ARRAY['block_ip', 'alert_soc'], 10),
('medium_confidence_monitoring', 'execution', '{"min_confidence": 0.65, "max_risk_score": 6}', ARRAY['monitor', 'log'], 50),
('low_confidence_logging', 'execution', '{"min_confidence": 0.50}', ARRAY['log'], 100);

COMMIT;