package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MigrateFromJSON migrates data from JSON files to SQLite database
func MigrateFromJSON(dbPath, jsonDir string) error {
	db, err := NewDB(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	defer db.Close()

	// Migrate scan_history.json
	scanHistoryPath := filepath.Join(jsonDir, "scan_history.json")
	if err := migrateScanHistory(db, scanHistoryPath); err != nil {
		return fmt.Errorf("scan history migration failed: %w", err)
	}

	// Migrate current_assignment.json
	assignmentPath := filepath.Join(jsonDir, "current_assignment.json")
	if err := migrateAssignment(db, assignmentPath); err != nil {
		return fmt.Errorf("assignment migration failed: %w", err)
	}

	// Migrate customer_traceroutes.json
	traceroutePath := filepath.Join(jsonDir, "customer_traceroutes.json")
	if err := migrateTraceroutes(db, traceroutePath); err != nil {
		return fmt.Errorf("traceroute migration failed: %w", err)
	}

	return nil
}

// migrateScanHistory migrates scan_history.json to the database
func migrateScanHistory(db *DB, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, skip migration
			return nil
		}
		return err
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	for _, entry := range entries {
		scanEntry := ScanHistoryEntry{
			CustomerID:       getStringField(entry, "customer_id"),
			CustomerName:     getStringField(entry, "customer_name"),
			ConfidenceScore:  getFloatField(entry, "confidence_score"),
			ExitIP:           getStringField(entry, "exit_ip"),
			HopCount:         getIntField(entry, "hop_count"),
			PrivateHopCount:  getIntField(entry, "private_hop_count"),
			PublicHopCount:   getIntField(entry, "public_hop_count"),
			NetworkSignature: getStringField(entry, "network_signature"),
			RawTraceroute:    getStringField(entry, "raw_traceroute"),
		}

		// Parse timestamp
		if ts, ok := entry["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				scanEntry.Timestamp = t
			} else {
				scanEntry.Timestamp = time.Now()
			}
		} else {
			scanEntry.Timestamp = time.Now()
		}

		// Parse network_key
		if nk, ok := entry["network_key"].(map[string]interface{}); ok {
			scanEntry.NetworkKey = nk
		} else {
			scanEntry.NetworkKey = make(map[string]interface{})
		}

		if err := db.InsertScanHistory(scanEntry); err != nil {
			return fmt.Errorf("failed to insert scan history entry: %w", err)
		}
	}

	return nil
}

// migrateAssignment migrates current_assignment.json to the database
func migrateAssignment(db *DB, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, skip migration
			return nil
		}
		return err
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}

	// Check if the entry is empty
	if len(entry) == 0 {
		return nil
	}

	assign := Assignment{
		CustomerID:   getStringField(entry, "customer_id"),
		CustomerName: getStringField(entry, "customer_name"),
		Confidence:   getFloatField(entry, "confidence"),
	}

	// Parse timestamp
	if ts, ok := entry["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			assign.Timestamp = t
		} else {
			assign.Timestamp = time.Now()
		}
	} else {
		assign.Timestamp = time.Now()
	}

	// Parse network_key
	if nk, ok := entry["network_key"].(map[string]interface{}); ok {
		assign.NetworkKey = nk
	} else {
		assign.NetworkKey = make(map[string]interface{})
	}

	return db.SetCurrentAssignment(assign)
}

// migrateTraceroutes migrates customer_traceroutes.json to the database
func migrateTraceroutes(db *DB, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, skip migration
			return nil
		}
		return err
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	for _, entry := range entries {
		trEntry := TracerouteEntry{
			ExitIP:    getStringField(entry, "exit_ip"),
			RawOutput: getStringField(entry, "raw"),
		}

		// Parse timestamp
		if ts, ok := entry["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				trEntry.Timestamp = t
			} else {
				trEntry.Timestamp = time.Now()
			}
		} else {
			trEntry.Timestamp = time.Now()
		}

		// Parse hops
		if hops, ok := entry["hops"].([]interface{}); ok {
			trEntry.Hops = make([]map[string]interface{}, 0, len(hops))
			for _, hop := range hops {
				if hopMap, ok := hop.(map[string]interface{}); ok {
					trEntry.Hops = append(trEntry.Hops, hopMap)
				}
			}
		} else {
			trEntry.Hops = make([]map[string]interface{}, 0)
		}

		if err := db.InsertTraceroute(trEntry); err != nil {
			return fmt.Errorf("failed to insert traceroute entry: %w", err)
		}
	}

	return nil
}

// Helper functions to safely extract fields from map[string]interface{}

func getStringField(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getFloatField(m map[string]interface{}, key string) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	if val, ok := m[key].(int); ok {
		return float64(val)
	}
	return 0.0
}

func getIntField(m map[string]interface{}, key string) int {
	if val, ok := m[key].(float64); ok {
		return int(val)
	}
	if val, ok := m[key].(int); ok {
		return val
	}
	return 0
}
