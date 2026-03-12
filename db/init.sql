
-- TABEL: assets (CMDB Dummy)
CREATE TABLE IF NOT EXISTS assets (
    asset_id        VARCHAR(100) PRIMARY KEY,
    hostname        VARCHAR(100) NOT NULL,
    asset_type      VARCHAR(50)  NOT NULL,  -- server, workstation, application
    criticality     VARCHAR(20)  NOT NULL,  -- low, medium, high, critical
    criticality_score INTEGER    NOT NULL,  -- 1-10
    department      VARCHAR(100),
    ip_address      VARCHAR(50),
    created_at      TIMESTAMP DEFAULT NOW()
);

-- TABEL: wazuh_events (Telemetri Input)
CREATE TABLE IF NOT EXISTS wazuh_events (
    id              SERIAL PRIMARY KEY,
    event_id        UUID DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMP NOT NULL,
    asset_id        VARCHAR(100) REFERENCES assets(asset_id),
    hostname        VARCHAR(100),
    severity        INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 15),
    category        VARCHAR(50),   -- auth, malware, integrity, network
    event_type      VARCHAR(50),   -- alert, vuln, control
    rule_id         VARCHAR(50),
    rule_description TEXT,
    cve_id          VARCHAR(50),   -- untuk event_type = vuln
    cvss_score      NUMERIC(4,1),  -- untuk event_type = vuln
    scenario        VARCHAR(50),   -- normal, spike, vuln, decay
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Index untuk query performa
CREATE INDEX IF NOT EXISTS idx_events_asset_id    ON wazuh_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON wazuh_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity    ON wazuh_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_scenario    ON wazuh_events(scenario);

-- TABEL: risk_scores (Output Scoring Engine)
CREATE TABLE IF NOT EXISTS risk_scores (
    id              SERIAL PRIMARY KEY,
    asset_id        VARCHAR(100) REFERENCES assets(asset_id),
    risk_score      NUMERIC(5,2) NOT NULL,
    threat_score    NUMERIC(5,2),
    vuln_score      NUMERIC(5,2),
    criticality_score NUMERIC(5,2),
    calculated_at   TIMESTAMP NOT NULL,
    window_hours    INTEGER DEFAULT 24,  -- window perhitungan
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scores_asset_id ON risk_scores(asset_id);
CREATE INDEX IF NOT EXISTS idx_scores_calculated_at ON risk_scores(calculated_at);