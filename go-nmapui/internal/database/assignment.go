package database

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Assignment represents the current customer assignment
type Assignment struct {
	CustomerID   string                 `json:"customer_id"`
	CustomerName string                 `json:"customer_name"`
	Timestamp    time.Time              `json:"timestamp"`
	Confidence   float64                `json:"confidence"`
	NetworkKey   map[string]interface{} `json:"network_key"`
}

// SetCurrentAssignment sets or updates the current customer assignment
// Only one assignment can exist at a time (enforced by id = 1 constraint)
func (db *DB) SetCurrentAssignment(assign Assignment) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	networkKeyJSON, err := json.Marshal(assign.NetworkKey)
	if err != nil {
		return err
	}

	query := `INSERT OR REPLACE INTO current_assignment (
		id, customer_id, customer_name, timestamp, confidence, network_key_json
	) VALUES (1, ?, ?, ?, ?, ?)`

	_, err = db.conn.Exec(query,
		assign.CustomerID, assign.CustomerName,
		assign.Timestamp, assign.Confidence, networkKeyJSON,
	)
	return err
}

// GetCurrentAssignment retrieves the current customer assignment
// Returns nil if no assignment exists
func (db *DB) GetCurrentAssignment() (*Assignment, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	query := `SELECT customer_id, customer_name, timestamp, confidence, network_key_json
	          FROM current_assignment WHERE id = 1`

	var assign Assignment
	var networkKeyJSON string

	err := db.conn.QueryRow(query).Scan(
		&assign.CustomerID, &assign.CustomerName,
		&assign.Timestamp, &assign.Confidence, &networkKeyJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(networkKeyJSON), &assign.NetworkKey); err != nil {
		return nil, err
	}

	return &assign, nil
}

// ClearCurrentAssignment removes the current customer assignment
func (db *DB) ClearCurrentAssignment() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.Exec("DELETE FROM current_assignment WHERE id = 1")
	return err
}

// HasCurrentAssignment checks if a current assignment exists
func (db *DB) HasCurrentAssignment() (bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM current_assignment WHERE id = 1").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
