package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/techmore/nmapui/internal/database"
	"github.com/techmore/nmapui/internal/fingerprint"
	"github.com/techmore/nmapui/internal/models"
	"github.com/techmore/nmapui/internal/scanner"
	"github.com/techmore/nmapui/pkg/websocket"
)

func setupTestServer(t *testing.T) (*Server, func()) {
	t.Helper()

	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	fp := fingerprint.NewCustomerFingerprinter("../../config/customers.yaml")
	nmapScanner := scanner.NewNmapScanner("nmap")
	scanEngine := scanner.NewScanEngine(nmapScanner, nil, 5)
	hub := websocket.NewHub()

	deps := &Dependencies{
		DB:            db,
		ScanEngine:    scanEngine,
		Fingerprinter: fp,
		WSHub:         hub,
	}

	server := NewServer(deps)
	if err := server.Initialize(); err != nil {
		t.Fatalf("failed to initialize server: %v", err)
	}

	cleanup := func() {
		db.Close()
	}

	return server, cleanup
}

func TestHandleVersion(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/version", nil)
	resp, err := server.App.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["app_version"] != "1.0.0-go" {
		t.Errorf("expected app_version '1.0.0-go', got %v", result["app_version"])
	}

	if result["status"] != "running" {
		t.Errorf("expected status 'running', got %v", result["status"])
	}
}

func TestHandleGetCustomers(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/customers", nil)
	resp, err := server.App.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	customers, ok := result["customers"].([]interface{})
	if !ok {
		t.Fatal("customers field missing or wrong type")
	}

	total, ok := result["total"].(float64)
	if !ok {
		t.Fatal("total field missing or wrong type")
	}

	if int(total) != len(customers) {
		t.Errorf("total (%d) doesn't match customers length (%d)", int(total), len(customers))
	}
}

func TestHandleGetCustomer(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name       string
		customerID string
		wantStatus int
	}{
		{
			name:       "valid customer",
			customerID: "demo-customer-1",
			wantStatus: fiber.StatusOK,
		},
		{
			name:       "nonexistent customer",
			customerID: "nonexistent",
			wantStatus: fiber.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/customers/"+tt.customerID, nil)
			resp, err := server.App.Test(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestHandleAssignCustomer(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
		wantError  bool
	}{
		{
			name: "valid customer",
			body: map[string]interface{}{
				"customer_id": "demo-customer-1",
			},
			wantStatus: fiber.StatusOK,
			wantError:  false,
		},
		{
			name: "nonexistent customer",
			body: map[string]interface{}{
				"customer_id": "nonexistent",
			},
			wantStatus: fiber.StatusNotFound,
			wantError:  true,
		},
		{
			name:       "missing customer_id",
			body:       map[string]interface{}{},
			wantStatus: fiber.StatusNotFound,
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/customer/assign", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := server.App.Test(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("expected status %d, got %d. Body: %s", tt.wantStatus, resp.StatusCode, string(body))
			}
		})
	}
}

func TestHandleGetCurrentAssignment(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/customer/current", nil)
	resp, err := server.App.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, exists := result["customer"]; !exists {
		t.Error("response missing 'customer' field")
	}
}

func TestHandleListScans(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name       string
		queryLimit string
		wantStatus int
	}{
		{
			name:       "default limit",
			queryLimit: "",
			wantStatus: fiber.StatusOK,
		},
		{
			name:       "custom limit",
			queryLimit: "?limit=10",
			wantStatus: fiber.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/scans"+tt.queryLimit, nil)
			resp, err := server.App.Test(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if _, exists := result["scans"]; !exists {
				t.Error("response missing 'scans' field")
			}
			if _, exists := result["total"]; !exists {
				t.Error("response missing 'total' field")
			}
		})
	}
}

func TestHandleScanHistory(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/scan/history", nil)
	resp, err := server.App.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, exists := result["history"]; !exists {
		t.Error("response missing 'history' field")
	}
}

func TestHandleStartScan(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name:       "missing target",
			body:       map[string]interface{}{},
			wantStatus: fiber.StatusBadRequest,
		},
		{
			name: "invalid scan type",
			body: map[string]interface{}{
				"target":    "127.0.0.1",
				"scan_type": "invalid",
			},
			wantStatus: fiber.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/scan/start", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := server.App.Test(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestHandleQuickScan(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name:       "missing target",
			body:       map[string]interface{}{},
			wantStatus: fiber.StatusBadRequest,
		},
		{
			name: "empty target",
			body: map[string]interface{}{
				"target": "",
			},
			wantStatus: fiber.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/scan/quick", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := server.App.Test(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestHandleDeepScan(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name:       "missing targets",
			body:       map[string]interface{}{},
			wantStatus: fiber.StatusBadRequest,
		},
		{
			name: "empty targets array",
			body: map[string]interface{}{
				"targets": []string{},
			},
			wantStatus: fiber.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/scan/deep", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := server.App.Test(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestHandleNotImplementedEndpoints(t *testing.T) {
	t.Skip("Not-implemented endpoints are not registered in routes yet")
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal-file.txt", "normal-file.txt"},
		{"file with spaces", "file_with_spaces"},
		{"file/with/slashes", "file_with_slashes"},
		{"file@#$%special", "file____special"},
		{"CamelCase123", "CamelCase123"},
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

func TestExtractNetworkKey(t *testing.T) {
	tests := []struct {
		name  string
		hosts []models.Host
		want  bool
	}{
		{
			name:  "empty hosts",
			hosts: []models.Host{},
			want:  false,
		},
		{
			name: "single host",
			hosts: []models.Host{
				{IP: "192.168.1.1"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNetworkKey(tt.hosts)

			if tt.want {
				if exitIP, ok := result["exit_ip"].(string); !ok || exitIP == "" {
					t.Error("expected exit_ip to be set")
				}
			} else {
				if len(result) > 0 {
					if _, ok := result["exit_ip"]; ok {
						t.Error("expected empty result for no hosts")
					}
				}
			}
		})
	}
}
