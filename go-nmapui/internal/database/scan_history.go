package database

import (
	"database/sql"
	"encoding/json"
	"time"
)

// ScanHistoryEntry represents a single scan history record
type ScanHistoryEntry struct {
	ID               int64                  `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	CustomerID       string                 `json:"customer_id"`
	CustomerName     string                 `json:"customer_name"`
	ConfidenceScore  float64                `json:"confidence_score"`
	ExitIP           string                 `json:"exit_ip"`
	HopCount         int                    `json:"hop_count"`
	PrivateHopCount  int                    `json:"private_hop_count"`
	PublicHopCount   int                    `json:"public_hop_count"`
	NetworkSignature string                 `json:"network_signature"`
	RawTraceroute    string                 `json:"raw_traceroute"`
	NetworkKey       map[string]interface{} `json:"network_key"`
}

// InsertScanHistory adds a new scan history entry to the database
func (db *DB) InsertScanHistory(entry ScanHistoryEntry) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	networkKeyJSON, err := json.Marshal(entry.NetworkKey)
	if err != nil {
		return err
	}

	query := `INSERT INTO scan_history (
		timestamp, customer_id, customer_name, confidence_score,
		exit_ip, hop_count, private_hop_count, public_hop_count,
		network_signature, raw_traceroute, network_key_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = db.conn.Exec(query,
		entry.Timestamp, entry.CustomerID, entry.CustomerName,
		entry.ConfidenceScore, entry.ExitIP, entry.HopCount,
		entry.PrivateHopCount, entry.PublicHopCount,
		entry.NetworkSignature, entry.RawTraceroute, networkKeyJSON,
	)
	return err
}

// GetScanHistory retrieves scan history entries, optionally filtered by customer ID
func (db *DB) GetScanHistory(customerID string, limit int) ([]ScanHistoryEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `SELECT id, timestamp, customer_id, customer_name, confidence_score,
	                 exit_ip, hop_count, private_hop_count, public_hop_count,
	                 network_signature, raw_traceroute, network_key_json
	          FROM scan_history`

	args := []interface{}{}
	if customerID != "" {
		query += " WHERE customer_id = ?"
		args = append(args, customerID)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []ScanHistoryEntry
	for rows.Next() {
		var entry ScanHistoryEntry
		var networkKeyJSON string

		err := rows.Scan(
			&entry.ID, &entry.Timestamp, &entry.CustomerID, &entry.CustomerName,
			&entry.ConfidenceScore, &entry.ExitIP, &entry.HopCount,
			&entry.PrivateHopCount, &entry.PublicHopCount,
			&entry.NetworkSignature, &entry.RawTraceroute, &networkKeyJSON,
		)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(networkKeyJSON), &entry.NetworkKey); err != nil {
			return nil, err
		}

		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// GetAllScanHistory retrieves all scan history entries up to the specified limit
func (db *DB) GetAllScanHistory(limit int) ([]ScanHistoryEntry, error) {
	return db.GetScanHistory("", limit)
}

// PruneOldScans removes old scan history entries, keeping only the most recent maxEntries
func (db *DB) PruneOldScans(maxEntries int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `DELETE FROM scan_history WHERE id NOT IN (
		SELECT id FROM scan_history ORDER BY timestamp DESC LIMIT ?
	)`
	_, err := db.conn.Exec(query, maxEntries)
	return err
}

// GetScanHistoryCount returns the total number of scan history entries
func (db *DB) GetScanHistoryCount() (int, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM scan_history").Scan(&count)
	return count, err
}

// GetScanHistoryByID retrieves a single scan history entry by ID
func (db *DB) GetScanHistoryByID(id int64) (*ScanHistoryEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `SELECT id, timestamp, customer_id, customer_name, confidence_score,
	                 exit_ip, hop_count, private_hop_count, public_hop_count,
	                 network_signature, raw_traceroute, network_key_json
	          FROM scan_history WHERE id = ?`

	var entry ScanHistoryEntry
	var networkKeyJSON string

	err := db.conn.QueryRow(query, id).Scan(
		&entry.ID, &entry.Timestamp, &entry.CustomerID, &entry.CustomerName,
		&entry.ConfidenceScore, &entry.ExitIP, &entry.HopCount,
		&entry.PrivateHopCount, &entry.PublicHopCount,
		&entry.NetworkSignature, &entry.RawTraceroute, &networkKeyJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(networkKeyJSON), &entry.NetworkKey); err != nil {
		return nil, err
	}

	return &entry, nil
}
