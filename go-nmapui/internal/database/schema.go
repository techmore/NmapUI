package database

// Schema defines the SQLite database schema for NmapUI
const Schema = `
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    customer_id TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    confidence_score REAL NOT NULL,
    exit_ip TEXT,
    hop_count INTEGER,
    private_hop_count INTEGER,
    public_hop_count INTEGER,
    network_signature TEXT,
    raw_traceroute TEXT,
    network_key_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_history_customer ON scan_history(customer_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp DESC);

CREATE TABLE IF NOT EXISTS current_assignment (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Only one row
    customer_id TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    confidence REAL NOT NULL,
    network_key_json TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS traceroute_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    exit_ip TEXT NOT NULL,
    hops_json TEXT NOT NULL,
    raw_output TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_traceroute_exit_ip ON traceroute_history(exit_ip);
CREATE INDEX IF NOT EXISTS idx_traceroute_timestamp ON traceroute_history(timestamp DESC);
`
