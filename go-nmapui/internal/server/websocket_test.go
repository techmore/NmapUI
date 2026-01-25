package server

import (
	"testing"
	"time"

	"github.com/techmore/nmapui/internal/database"
	"github.com/techmore/nmapui/internal/fingerprint"
	"github.com/techmore/nmapui/internal/scanner"
	nmapws "github.com/techmore/nmapui/pkg/websocket"
)

func setupWSTestServer(t *testing.T) (*Server, func()) {
	t.Helper()

	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	fp := fingerprint.NewCustomerFingerprinter("../../config/customers.yaml")
	nmapScanner := scanner.NewNmapScanner("nmap")
	scanEngine := scanner.NewScanEngine(nmapScanner, nil, 5)
	hub := nmapws.NewHub()

	deps := &Dependencies{
		DB:            db,
		ScanEngine:    scanEngine,
		Fingerprinter: fp,
		WSHub:         hub,
	}

	server := NewServer(deps)

	cleanup := func() {
		db.Close()
	}

	return server, cleanup
}

func TestHandleAssignCustomerWS_Database(t *testing.T) {
	server, cleanup := setupWSTestServer(t)
	defer cleanup()

	tests := []struct {
		name        string
		customerID  string
		expectSaved bool
	}{
		{
			name:        "valid customer assignment",
			customerID:  "demo-customer-1",
			expectSaved: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assignment := database.Assignment{
				CustomerID:   tt.customerID,
				CustomerName: tt.customerID,
				Timestamp:    time.Now(),
				Confidence:   1.0,
				NetworkKey:   make(map[string]interface{}),
			}

			err := server.Deps.DB.SetCurrentAssignment(assignment)
			if err != nil {
				t.Fatalf("failed to save assignment: %v", err)
			}

			if tt.expectSaved {
				saved, err := server.Deps.DB.GetCurrentAssignment()
				if err != nil {
					t.Fatalf("failed to get assignment: %v", err)
				}

				if saved == nil {
					t.Fatal("expected assignment to be saved")
				}

				if saved.CustomerID != tt.customerID {
					t.Errorf("expected customer_id %s, got %s", tt.customerID, saved.CustomerID)
				}
			}
		})
	}
}

func TestHandleSearchScanHistoryWS_Database(t *testing.T) {
	server, cleanup := setupWSTestServer(t)
	defer cleanup()

	testData := []database.ScanHistoryEntry{
		{
			Timestamp:       time.Now(),
			CustomerID:      "customer-1",
			CustomerName:    "Customer One",
			ConfidenceScore: 0.95,
			NetworkKey:      map[string]interface{}{"exit_ip": "1.2.3.4"},
		},
		{
			Timestamp:       time.Now().Add(-1 * time.Hour),
			CustomerID:      "customer-2",
			CustomerName:    "Customer Two",
			ConfidenceScore: 0.85,
			NetworkKey:      map[string]interface{}{"exit_ip": "5.6.7.8"},
		},
	}

	for _, entry := range testData {
		if err := server.Deps.DB.InsertScanHistory(entry); err != nil {
			t.Fatalf("failed to insert test data: %v", err)
		}
	}

	tests := []struct {
		name        string
		customerID  string
		limit       int
		expectCount int
	}{
		{
			name:        "all scans",
			customerID:  "",
			limit:       10,
			expectCount: 2,
		},
		{
			name:        "customer filter",
			customerID:  "customer-1",
			limit:       10,
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			history, err := server.Deps.DB.GetScanHistory(tt.customerID, tt.limit)
			if err != nil {
				t.Fatalf("GetScanHistory failed: %v", err)
			}

			if len(history) != tt.expectCount {
				t.Errorf("expected %d scans, got %d", tt.expectCount, len(history))
			}
		})
	}
}

func TestHandleGetHistoryCountsWS_Database(t *testing.T) {
	server, cleanup := setupWSTestServer(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		entry := database.ScanHistoryEntry{
			Timestamp:       time.Now().Add(time.Duration(-i) * time.Hour),
			CustomerID:      "test-customer",
			CustomerName:    "Test Corp",
			ConfidenceScore: 0.95,
			NetworkKey:      map[string]interface{}{"exit_ip": "1.2.3.4"},
		}

		if err := server.Deps.DB.InsertScanHistory(entry); err != nil {
			t.Fatalf("failed to insert test data: %v", err)
		}
	}

	count, err := server.Deps.DB.GetScanHistoryCount()
	if err != nil {
		t.Fatalf("GetScanHistoryCount failed: %v", err)
	}

	if count != 5 {
		t.Errorf("expected 5 scans, got %d", count)
	}
}

func TestHandleGetCustomersWS_Fingerprinter(t *testing.T) {
	server, cleanup := setupWSTestServer(t)
	defer cleanup()

	customers := server.Deps.Fingerprinter.Customers

	if len(customers) == 0 {
		t.Error("expected at least one customer from config")
	}

	for _, customer := range customers {
		if customer.ID == "" {
			t.Error("customer missing ID")
		}
		if customer.Name == "" {
			t.Error("customer missing Name")
		}
	}
}

func TestRegisterStub(t *testing.T) {
	t.Skip("Stub handler requires real client - tested via integration tests")
}

func TestRegisterWebSocketHandlers(t *testing.T) {
	t.Skip("WebSocket handlers require real client connections - tested via integration tests")
}

func TestSanitizeFilename_WebSocket(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"customer-1", "customer-1"},
		{"customer with spaces", "customer_with_spaces"},
		{"customer/slashes", "customer_slashes"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
