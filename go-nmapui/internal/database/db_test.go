package database

import (
	"testing"
	"time"
)

func setupTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	return db
}

func TestNewDB(t *testing.T) {
	tests := []struct {
		name    string
		dbPath  string
		wantErr bool
	}{
		{
			name:    "in-memory database",
			dbPath:  ":memory:",
			wantErr: false,
		},
		{
			name:    "invalid path",
			dbPath:  "/invalid/path/that/does/not/exist/db.sqlite",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(tt.dbPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && db != nil {
				defer db.Close()
				// Verify connection works
				if err := db.Ping(); err != nil {
					t.Errorf("Ping() failed: %v", err)
				}
			}
		})
	}
}

func TestDB_Ping(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Errorf("Ping() error = %v", err)
	}
}

func TestDB_Begin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer tx.Rollback()

	if tx == nil {
		t.Error("Begin() returned nil transaction")
	}
}

func TestDB_Close(t *testing.T) {
	db := setupTestDB(t)

	if err := db.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify database is closed
	if err := db.Ping(); err == nil {
		t.Error("Ping() should fail after Close()")
	}
}

func TestDB_ScanHistory(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	entry := ScanHistoryEntry{
		Timestamp:        time.Now(),
		CustomerID:       "test123",
		CustomerName:     "Test Corp",
		ConfidenceScore:  0.95,
		ExitIP:           "203.0.113.1",
		HopCount:         12,
		PrivateHopCount:  8,
		PublicHopCount:   4,
		NetworkSignature: "private:10.0.x.x -> public:203.0.x.x",
		RawTraceroute:    "traceroute output here",
		NetworkKey: map[string]interface{}{
			"exit_ip": "203.0.113.1",
			"hops":    12,
		},
	}

	// Test insert
	err := db.InsertScanHistory(entry)
	if err != nil {
		t.Fatalf("InsertScanHistory() error = %v", err)
	}

	// Test retrieve by customer ID
	results, err := db.GetScanHistory("test123", 10)
	if err != nil {
		t.Fatalf("GetScanHistory() error = %v", err)
	}

	if len(results) != 1 {
		t.Errorf("GetScanHistory() returned %d results, want 1", len(results))
	}

	if len(results) > 0 {
		result := results[0]
		if result.CustomerID != "test123" {
			t.Errorf("CustomerID = %s, want test123", result.CustomerID)
		}
		if result.CustomerName != "Test Corp" {
			t.Errorf("CustomerName = %s, want Test Corp", result.CustomerName)
		}
		if result.ConfidenceScore != 0.95 {
			t.Errorf("ConfidenceScore = %f, want 0.95", result.ConfidenceScore)
		}
		if result.ExitIP != "203.0.113.1" {
			t.Errorf("ExitIP = %s, want 203.0.113.1", result.ExitIP)
		}
		if result.HopCount != 12 {
			t.Errorf("HopCount = %d, want 12", result.HopCount)
		}
		if result.NetworkKey == nil {
			t.Error("NetworkKey is nil")
		}
	}

	// Test retrieve all
	allResults, err := db.GetAllScanHistory(10)
	if err != nil {
		t.Fatalf("GetAllScanHistory() error = %v", err)
	}

	if len(allResults) != 1 {
		t.Errorf("GetAllScanHistory() returned %d results, want 1", len(allResults))
	}
}

func TestDB_ScanHistoryMultiple(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert multiple entries
	for i := 0; i < 5; i++ {
		entry := ScanHistoryEntry{
			Timestamp:       time.Now().Add(time.Duration(i) * time.Minute),
			CustomerID:      "cust1",
			CustomerName:    "Customer 1",
			ConfidenceScore: 0.9,
			ExitIP:          "203.0.113.1",
			HopCount:        10,
			NetworkKey:      map[string]interface{}{"test": i},
		}
		if err := db.InsertScanHistory(entry); err != nil {
			t.Fatalf("InsertScanHistory() error = %v", err)
		}
	}

	// Insert entries for different customer
	for i := 0; i < 3; i++ {
		entry := ScanHistoryEntry{
			Timestamp:       time.Now().Add(time.Duration(i) * time.Minute),
			CustomerID:      "cust2",
			CustomerName:    "Customer 2",
			ConfidenceScore: 0.85,
			ExitIP:          "203.0.113.2",
			HopCount:        8,
			NetworkKey:      map[string]interface{}{"test": i},
		}
		if err := db.InsertScanHistory(entry); err != nil {
			t.Fatalf("InsertScanHistory() error = %v", err)
		}
	}

	// Test filtering by customer
	cust1Results, err := db.GetScanHistory("cust1", 10)
	if err != nil {
		t.Fatalf("GetScanHistory() error = %v", err)
	}
	if len(cust1Results) != 5 {
		t.Errorf("GetScanHistory(cust1) returned %d results, want 5", len(cust1Results))
	}

	cust2Results, err := db.GetScanHistory("cust2", 10)
	if err != nil {
		t.Fatalf("GetScanHistory() error = %v", err)
	}
	if len(cust2Results) != 3 {
		t.Errorf("GetScanHistory(cust2) returned %d results, want 3", len(cust2Results))
	}

	// Test limit
	limitedResults, err := db.GetScanHistory("cust1", 2)
	if err != nil {
		t.Fatalf("GetScanHistory() error = %v", err)
	}
	if len(limitedResults) != 2 {
		t.Errorf("GetScanHistory() with limit 2 returned %d results, want 2", len(limitedResults))
	}
}

func TestDB_GetScanHistoryByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	entry := ScanHistoryEntry{
		Timestamp:       time.Now(),
		CustomerID:      "test123",
		CustomerName:    "Test Corp",
		ConfidenceScore: 0.95,
		NetworkKey:      map[string]interface{}{"test": "data"},
	}

	if err := db.InsertScanHistory(entry); err != nil {
		t.Fatalf("InsertScanHistory() error = %v", err)
	}

	// Get all to find the ID
	results, err := db.GetScanHistory("test123", 1)
	if err != nil || len(results) == 0 {
		t.Fatalf("GetScanHistory() failed to retrieve entry")
	}

	id := results[0].ID

	// Test GetScanHistoryByID
	result, err := db.GetScanHistoryByID(id)
	if err != nil {
		t.Fatalf("GetScanHistoryByID() error = %v", err)
	}

	if result == nil {
		t.Fatal("GetScanHistoryByID() returned nil")
	}

	if result.CustomerID != "test123" {
		t.Errorf("CustomerID = %s, want test123", result.CustomerID)
	}

	// Test non-existent ID
	result, err = db.GetScanHistoryByID(99999)
	if err != nil {
		t.Errorf("GetScanHistoryByID() with invalid ID error = %v", err)
	}
	if result != nil {
		t.Error("GetScanHistoryByID() should return nil for non-existent ID")
	}
}

func TestDB_GetScanHistoryCount(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Initially should be 0
	count, err := db.GetScanHistoryCount()
	if err != nil {
		t.Fatalf("GetScanHistoryCount() error = %v", err)
	}
	if count != 0 {
		t.Errorf("GetScanHistoryCount() = %d, want 0", count)
	}

	// Insert entries
	for i := 0; i < 5; i++ {
		entry := ScanHistoryEntry{
			Timestamp:    time.Now(),
			CustomerID:   "test",
			CustomerName: "Test",
			NetworkKey:   map[string]interface{}{},
		}
		if err := db.InsertScanHistory(entry); err != nil {
			t.Fatalf("InsertScanHistory() error = %v", err)
		}
	}

	count, err = db.GetScanHistoryCount()
	if err != nil {
		t.Fatalf("GetScanHistoryCount() error = %v", err)
	}
	if count != 5 {
		t.Errorf("GetScanHistoryCount() = %d, want 5", count)
	}
}

func TestDB_PruneOldScans(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert 10 entries
	for i := 0; i < 10; i++ {
		entry := ScanHistoryEntry{
			Timestamp:    time.Now().Add(time.Duration(i) * time.Minute),
			CustomerID:   "test",
			CustomerName: "Test",
			NetworkKey:   map[string]interface{}{},
		}
		if err := db.InsertScanHistory(entry); err != nil {
			t.Fatalf("InsertScanHistory() error = %v", err)
		}
	}

	// Prune to keep only 5
	if err := db.PruneOldScans(5); err != nil {
		t.Fatalf("PruneOldScans() error = %v", err)
	}

	count, err := db.GetScanHistoryCount()
	if err != nil {
		t.Fatalf("GetScanHistoryCount() error = %v", err)
	}
	if count != 5 {
		t.Errorf("After pruning, count = %d, want 5", count)
	}
}

func TestDB_CurrentAssignment(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Initially should have no assignment
	result, err := db.GetCurrentAssignment()
	if err != nil {
		t.Fatalf("GetCurrentAssignment() error = %v", err)
	}
	if result != nil {
		t.Error("GetCurrentAssignment() should return nil initially")
	}

	// Check HasCurrentAssignment
	has, err := db.HasCurrentAssignment()
	if err != nil {
		t.Fatalf("HasCurrentAssignment() error = %v", err)
	}
	if has {
		t.Error("HasCurrentAssignment() should return false initially")
	}

	// Set assignment
	assign := Assignment{
		CustomerID:   "cust456",
		CustomerName: "ACME Corp",
		Timestamp:    time.Now(),
		Confidence:   0.85,
		NetworkKey: map[string]interface{}{
			"test": "data",
			"exit_ip": "203.0.113.1",
		},
	}

	err = db.SetCurrentAssignment(assign)
	if err != nil {
		t.Fatalf("SetCurrentAssignment() error = %v", err)
	}

	// Get assignment
	result, err = db.GetCurrentAssignment()
	if err != nil {
		t.Fatalf("GetCurrentAssignment() error = %v", err)
	}

	if result == nil {
		t.Fatal("GetCurrentAssignment() returned nil")
	}

	if result.CustomerID != "cust456" {
		t.Errorf("CustomerID = %s, want cust456", result.CustomerID)
	}
	if result.CustomerName != "ACME Corp" {
		t.Errorf("CustomerName = %s, want ACME Corp", result.CustomerName)
	}
	if result.Confidence != 0.85 {
		t.Errorf("Confidence = %f, want 0.85", result.Confidence)
	}
	if result.NetworkKey == nil {
		t.Error("NetworkKey is nil")
	}

	// Check HasCurrentAssignment
	has, err = db.HasCurrentAssignment()
	if err != nil {
		t.Fatalf("HasCurrentAssignment() error = %v", err)
	}
	if !has {
		t.Error("HasCurrentAssignment() should return true")
	}

	// Update assignment (replace)
	newAssign := Assignment{
		CustomerID:   "cust789",
		CustomerName: "New Corp",
		Timestamp:    time.Now(),
		Confidence:   0.95,
		NetworkKey:   map[string]interface{}{"new": "data"},
	}

	err = db.SetCurrentAssignment(newAssign)
	if err != nil {
		t.Fatalf("SetCurrentAssignment() update error = %v", err)
	}

	result, err = db.GetCurrentAssignment()
	if err != nil {
		t.Fatalf("GetCurrentAssignment() error = %v", err)
	}

	if result.CustomerID != "cust789" {
		t.Errorf("After update, CustomerID = %s, want cust789", result.CustomerID)
	}

	// Clear assignment
	err = db.ClearCurrentAssignment()
	if err != nil {
		t.Fatalf("ClearCurrentAssignment() error = %v", err)
	}

	result, err = db.GetCurrentAssignment()
	if err != nil {
		t.Fatalf("GetCurrentAssignment() error = %v", err)
	}
	if result != nil {
		t.Error("GetCurrentAssignment() should return nil after clear")
	}

	has, err = db.HasCurrentAssignment()
	if err != nil {
		t.Fatalf("HasCurrentAssignment() error = %v", err)
	}
	if has {
		t.Error("HasCurrentAssignment() should return false after clear")
	}
}

// Benchmark tests
func BenchmarkInsertScanHistory(b *testing.B) {
	db, err := NewDB(":memory:")
	if err != nil {
		b.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	entry := ScanHistoryEntry{
		Timestamp:       time.Now(),
		CustomerID:      "test",
		CustomerName:    "Test",
		ConfidenceScore: 0.9,
		NetworkKey:      map[string]interface{}{"test": "data"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.InsertScanHistory(entry)
	}
}

func BenchmarkGetScanHistory(b *testing.B) {
	db, err := NewDB(":memory:")
	if err != nil {
		b.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	// Insert test data
	for i := 0; i < 100; i++ {
		entry := ScanHistoryEntry{
			Timestamp:    time.Now(),
			CustomerID:   "test",
			CustomerName: "Test",
			NetworkKey:   map[string]interface{}{},
		}
		_ = db.InsertScanHistory(entry)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = db.GetScanHistory("test", 10)
	}
}

func BenchmarkSetCurrentAssignment(b *testing.B) {
	db, err := NewDB(":memory:")
	if err != nil {
		b.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	assign := Assignment{
		CustomerID:   "test",
		CustomerName: "Test",
		Timestamp:    time.Now(),
		Confidence:   0.9,
		NetworkKey:   map[string]interface{}{"test": "data"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.SetCurrentAssignment(assign)
	}
}
