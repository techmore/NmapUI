package database

import (
	"database/sql"
	"encoding/json"
	"time"
)

// TracerouteEntry represents a single traceroute history record
type TracerouteEntry struct {
	ID        int64                    `json:"id"`
	Timestamp time.Time                `json:"timestamp"`
	ExitIP    string                   `json:"exit_ip"`
	Hops      []map[string]interface{} `json:"hops"`
	RawOutput string                   `json:"raw"`
}

// InsertTraceroute adds a new traceroute entry to the database
func (db *DB) InsertTraceroute(entry TracerouteEntry) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	hopsJSON, err := json.Marshal(entry.Hops)
	if err != nil {
		return err
	}

	query := `INSERT INTO traceroute_history (timestamp, exit_ip, hops_json, raw_output)
	          VALUES (?, ?, ?, ?)`

	_, err = db.conn.Exec(query, entry.Timestamp, entry.ExitIP, hopsJSON, entry.RawOutput)
	return err
}

// GetTraceroutesByExitIP retrieves traceroute entries for a specific exit IP
func (db *DB) GetTraceroutesByExitIP(exitIP string, limit int) ([]TracerouteEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `SELECT id, timestamp, exit_ip, hops_json, raw_output
	          FROM traceroute_history WHERE exit_ip = ?
	          ORDER BY timestamp DESC LIMIT ?`

	rows, err := db.conn.Query(query, exitIP, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []TracerouteEntry
	for rows.Next() {
		var entry TracerouteEntry
		var hopsJSON string

		err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.ExitIP, &hopsJSON, &entry.RawOutput)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(hopsJSON), &entry.Hops); err != nil {
			return nil, err
		}

		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// GetAllTraceroutes retrieves all traceroute entries up to the specified limit
func (db *DB) GetAllTraceroutes(limit int) ([]TracerouteEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `SELECT id, timestamp, exit_ip, hops_json, raw_output
	          FROM traceroute_history
	          ORDER BY timestamp DESC LIMIT ?`

	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []TracerouteEntry
	for rows.Next() {
		var entry TracerouteEntry
		var hopsJSON string

		err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.ExitIP, &hopsJSON, &entry.RawOutput)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(hopsJSON), &entry.Hops); err != nil {
			return nil, err
		}

		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// GetTracerouteByID retrieves a single traceroute entry by ID
func (db *DB) GetTracerouteByID(id int64) (*TracerouteEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `SELECT id, timestamp, exit_ip, hops_json, raw_output
	          FROM traceroute_history WHERE id = ?`

	var entry TracerouteEntry
	var hopsJSON string

	err := db.conn.QueryRow(query, id).Scan(
		&entry.ID, &entry.Timestamp, &entry.ExitIP, &hopsJSON, &entry.RawOutput,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(hopsJSON), &entry.Hops); err != nil {
		return nil, err
	}

	return &entry, nil
}

// GetTracerouteCount returns the total number of traceroute entries
func (db *DB) GetTracerouteCount() (int, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM traceroute_history").Scan(&count)
	return count, err
}

// DeleteOldTraceroutes removes traceroute entries older than the specified time
func (db *DB) DeleteOldTraceroutes(olderThan time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.Exec("DELETE FROM traceroute_history WHERE timestamp < ?", olderThan)
	return err
}

// PruneOldTraceroutes removes old traceroute entries, keeping only the most recent maxEntries
func (db *DB) PruneOldTraceroutes(maxEntries int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	query := `DELETE FROM traceroute_history WHERE id NOT IN (
		SELECT id FROM traceroute_history ORDER BY timestamp DESC LIMIT ?
	)`
	_, err := db.conn.Exec(query, maxEntries)
	return err
}
