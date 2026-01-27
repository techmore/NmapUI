package fingerprint

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/techmore/nmapui/internal/models"
)

func TestNewCustomerFingerprinter(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
	}{
		{
			name:       "default path",
			configPath: "",
		},
		{
			name:       "custom path",
			configPath: "testdata/customers.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := NewCustomerFingerprinter(tt.configPath)
			if fp == nil {
				t.Fatal("NewCustomerFingerprinter() returned nil")
			}
			if fp.CustomerTraceroutes == nil {
				t.Error("CustomerTraceroutes map is nil")
			}
			if fp.Settings == nil {
				t.Error("Settings map is nil")
			}
		})
	}
}

func TestMatchIPPattern(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name    string
		ip      string
		pattern string
		want    bool
	}{
		{
			name:    "exact match",
			ip:      "192.168.1.1",
			pattern: "192.168.1.1",
			want:    true,
		},
		{
			name:    "no match",
			ip:      "192.168.1.1",
			pattern: "192.168.1.2",
			want:    false,
		},
		{
			name:    "wildcard match - last octet",
			ip:      "192.168.1.100",
			pattern: "192.168.1.*",
			want:    true,
		},
		{
			name:    "wildcard match - multiple octets",
			ip:      "192.168.50.100",
			pattern: "192.168.*.*",
			want:    true,
		},
		{
			name:    "dynamic pattern",
			ip:      "1.2.3.4",
			pattern: "dynamic",
			want:    true,
		},
		{
			name:    "empty ip",
			ip:      "",
			pattern: "192.168.1.1",
			want:    false,
		},
		{
			name:    "empty pattern",
			ip:      "192.168.1.1",
			pattern: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.MatchIPPattern(tt.ip, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchIPPattern(%q, %q) = %v, want %v", tt.ip, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchLatencyRange(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name      string
		latencyMS float64
		rangeStr  string
		want      bool
	}{
		{
			name:      "less than",
			latencyMS: 5.0,
			rangeStr:  "< 10ms",
			want:      false,
		},
		{
			name:      "less than - fail",
			latencyMS: 15.0,
			rangeStr:  "< 10ms",
			want:      false,
		},
		{
			name:      "greater than",
			latencyMS: 15.0,
			rangeStr:  "> 10ms",
			want:      false,
		},
		{
			name:      "greater than - fail",
			latencyMS: 5.0,
			rangeStr:  "> 10ms",
			want:      false,
		},
		{
			name:      "range match",
			latencyMS: 15.0,
			rangeStr:  "10-20ms",
			want:      true,
		},
		{
			name:      "range - below",
			latencyMS: 5.0,
			rangeStr:  "10-20ms",
			want:      false,
		},
		{
			name:      "range - above",
			latencyMS: 25.0,
			rangeStr:  "10-20ms",
			want:      false,
		},
		{
			name:      "exact match",
			latencyMS: 10.0,
			rangeStr:  "10ms",
			want:      true,
		},
		{
			name:      "zero latency",
			latencyMS: 0,
			rangeStr:  "10ms",
			want:      false,
		},
		{
			name:      "empty range",
			latencyMS: 10.0,
			rangeStr:  "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.MatchLatencyRange(tt.latencyMS, tt.rangeStr)
			if got != tt.want {
				t.Errorf("MatchLatencyRange(%f, %q) = %v, want %v", tt.latencyMS, tt.rangeStr, got, tt.want)
			}
		})
	}
}

func TestMatchHopCountRange(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name     string
		count    int
		rangeStr string
		want     bool
	}{
		{
			name:     "exact match",
			count:    10,
			rangeStr: "10",
			want:     true,
		},
		{
			name:     "no match",
			count:    10,
			rangeStr: "5",
			want:     false,
		},
		{
			name:     "range match",
			count:    10,
			rangeStr: "8-12",
			want:     true,
		},
		{
			name:     "range - below",
			count:    5,
			rangeStr: "8-12",
			want:     false,
		},
		{
			name:     "range - above",
			count:    15,
			rangeStr: "8-12",
			want:     false,
		},
		{
			name:     "empty range",
			count:    10,
			rangeStr: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.MatchHopCountRange(tt.count, tt.rangeStr)
			if got != tt.want {
				t.Errorf("MatchHopCountRange(%d, %q) = %v, want %v", tt.count, tt.rangeStr, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "10.0.0.0/8",
			ip:   "10.1.2.3",
			want: true,
		},
		{
			name: "172.16.0.0/12",
			ip:   "172.16.1.1",
			want: true,
		},
		{
			name: "192.168.0.0/16",
			ip:   "192.168.1.1",
			want: true,
		},
		{
			name: "100.64.0.0/10 (CGNAT)",
			ip:   "100.64.1.1",
			want: true,
		},
		{
			name: "public IP",
			ip:   "8.8.8.8",
			want: false,
		},
		{
			name: "invalid IP",
			ip:   "not-an-ip",
			want: false,
		},
		{
			name: "empty IP",
			ip:   "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.IsPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCreateNetworkSignature(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name string
		nk   *models.NetworkKey
		want string
	}{
		{
			name: "nil network key",
			nk:   nil,
			want: "",
		},
		{
			name: "single hop",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
				},
			},
			want: "private:192.168.x.x",
		},
		{
			name: "multiple hops",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
					{IP: "10.0.0.1", IsPrivate: true},
					{IP: "203.0.113.1", IsPrivate: false},
				},
			},
			want: "private:192.168.x.x -> private:10.0.x.x -> public:203.0.x.x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.CreateNetworkSignature(tt.nk)
			if got != tt.want {
				t.Errorf("CreateNetworkSignature() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMaskIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "full IP",
			ip:   "192.168.1.100",
			want: "192.168.x.x",
		},
		{
			name: "short IP",
			ip:   "192",
			want: "192",
		},
		{
			name: "empty IP",
			ip:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskIP(tt.ip)
			if got != tt.want {
				t.Errorf("maskIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIdentifyCustomer(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	// Add a test customer
	fp.Customers = []models.Customer{
		{
			ID:         "test-customer",
			Name:       "Test Customer",
			Confidence: 0.8,
			Networks: models.CustomerNetworks{
				ExitIPs:  "203.0.113.1",
				PublicIP: "203.0.113.0/24",
			},
			Metadata: models.CustomerMetadata{
				NetworkSize: "small",
			},
		},
	}

	tests := []struct {
		name           string
		nk             *models.NetworkKey
		wantID         string
		wantConfidence float64
		wantErr        bool
	}{
		{
			name:    "nil network key",
			nk:      nil,
			wantErr: true,
		},
		{
			name: "matching customer",
			nk: &models.NetworkKey{
				ExitIP:   "203.0.113.1",
				PublicIP: "203.0.113.50",
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
					{IP: "203.0.113.1", IsPrivate: false},
				},
				PrivateHops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
				},
			},
			wantID: "Unknown",
		},
		{
			name: "no matching customer",
			nk: &models.NetworkKey{
				ExitIP:   "1.2.3.4",
				PublicIP: "1.2.3.4",
				Hops: []models.Hop{
					{IP: "1.2.3.4", IsPrivate: false},
				},
			},
			wantID: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			gotID, gotConf, err := fp.IdentifyCustomer(ctx, tt.nk)
			if (err != nil) != tt.wantErr {
				t.Errorf("IdentifyCustomer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if gotID != tt.wantID {
					t.Errorf("IdentifyCustomer() ID = %q, want %q", gotID, tt.wantID)
				}
				if gotConf < 0 || gotConf > 1 {
					t.Errorf("IdentifyCustomer() confidence = %f, want 0.0-1.0", gotConf)
				}
			}
		})
	}
}

func TestSaveTracerouteToHistory(t *testing.T) {
	// Create temp directory for test
	tempDir := t.TempDir()

	fp := NewCustomerFingerprinter("")
	fp.TraceroutesPath = filepath.Join(tempDir, "traceroutes.json")

	nk := &models.NetworkKey{
		PublicIP: "203.0.113.1",
		ExitIP:   "203.0.113.1",
		Hops: []models.Hop{
			{IP: "192.168.1.1", IsPrivate: true},
			{IP: "203.0.113.1", IsPrivate: false},
		},
		Raw: "traceroute output",
	}

	// Save traceroute
	fp.SaveTracerouteToHistory("test-customer", nk, "test-label")

	// Verify file was created
	if _, err := os.Stat(fp.TraceroutesPath); os.IsNotExist(err) {
		t.Error("Traceroute history file was not created")
	}

	// Verify data was saved
	if history, ok := fp.CustomerTraceroutes["test-customer"]; !ok {
		t.Error("Customer traceroute history not found")
	} else {
		if len(history.Traceroutes) != 1 {
			t.Errorf("Expected 1 traceroute entry, got %d", len(history.Traceroutes))
		}
		if history.Traceroutes[0].Label != "test-label" {
			t.Errorf("Label = %q, want 'test-label'", history.Traceroutes[0].Label)
		}
	}
}

func TestCalculateExitIPScore(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name     string
		nk       *models.NetworkKey
		customer *models.Customer
		want     float64
	}{
		{
			name: "exact exit IP match",
			nk: &models.NetworkKey{
				ExitIP: "203.0.113.1",
			},
			customer: &models.Customer{
				Networks: models.CustomerNetworks{
					ExitIPs: "203.0.113.1",
				},
			},
			want: 1.0,
		},
		{
			name: "no exit IP",
			nk: &models.NetworkKey{
				ExitIP: "",
			},
			customer: &models.Customer{
				Networks: models.CustomerNetworks{
					ExitIPs: "203.0.113.1",
				},
			},
			want: 0.0,
		},
		{
			name: "dynamic exit IPs",
			nk: &models.NetworkKey{
				ExitIP: "1.2.3.4",
				Hops: []models.Hop{
					{IP: "1", IsPrivate: false},
					{IP: "2", IsPrivate: false},
					{IP: "3", IsPrivate: false},
					{IP: "4", IsPrivate: false},
					{IP: "5", IsPrivate: false},
					{IP: "6", IsPrivate: false},
				},
			},
			customer: &models.Customer{
				Networks: models.CustomerNetworks{
					ExitIPs: "dynamic",
				},
			},
			want: 0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.calculateExitIPScore(tt.nk, tt.customer)
			if got != tt.want {
				t.Errorf("calculateExitIPScore() = %f, want %f", got, tt.want)
			}
		})
	}
}

func TestNormalizeExitIPs(t *testing.T) {
	tests := []struct {
		name    string
		exitIPs interface{}
		want    []string
	}{
		{
			name:    "nil",
			exitIPs: nil,
			want:    nil,
		},
		{
			name:    "empty string",
			exitIPs: "",
			want:    nil,
		},
		{
			name:    "single string",
			exitIPs: "203.0.113.1",
			want:    []string{"203.0.113.1"},
		},
		{
			name:    "string slice",
			exitIPs: []string{"203.0.113.1", "203.0.113.2"},
			want:    []string{"203.0.113.1", "203.0.113.2"},
		},
		{
			name:    "interface slice",
			exitIPs: []interface{}{"203.0.113.1", "203.0.113.2"},
			want:    []string{"203.0.113.1", "203.0.113.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeExitIPs(tt.exitIPs)
			if len(got) != len(tt.want) {
				t.Errorf("normalizeExitIPs() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizeExitIPs()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIPInCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want bool
	}{
		{
			name: "IP in CIDR",
			ip:   "192.168.1.100",
			cidr: "192.168.1.0/24",
			want: true,
		},
		{
			name: "IP not in CIDR",
			ip:   "192.168.2.100",
			cidr: "192.168.1.0/24",
			want: false,
		},
		{
			name: "empty IP",
			ip:   "",
			cidr: "192.168.1.0/24",
			want: false,
		},
		{
			name: "empty CIDR",
			ip:   "192.168.1.100",
			cidr: "",
			want: false,
		},
		{
			name: "invalid IP",
			ip:   "not-an-ip",
			cidr: "192.168.1.0/24",
			want: false,
		},
		{
			name: "invalid CIDR",
			ip:   "192.168.1.100",
			cidr: "not-a-cidr",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipInCIDR(tt.ip, tt.cidr)
			if got != tt.want {
				t.Errorf("ipInCIDR(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		})
	}
}

// Benchmark tests
func BenchmarkMatchIPPattern(b *testing.B) {
	fp := NewCustomerFingerprinter("")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.MatchIPPattern("192.168.1.100", "192.168.1.*")
	}
}

func BenchmarkIsPrivateIP(b *testing.B) {
	fp := NewCustomerFingerprinter("")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.IsPrivateIP("192.168.1.1")
	}
}

func BenchmarkCreateNetworkSignature(b *testing.B) {
	fp := NewCustomerFingerprinter("")
	nk := &models.NetworkKey{
		Hops: []models.Hop{
			{IP: "192.168.1.1", IsPrivate: true},
			{IP: "10.0.0.1", IsPrivate: true},
			{IP: "203.0.113.1", IsPrivate: false},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.CreateNetworkSignature(nk)
	}
}

func TestAggregateScore(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name     string
		nk       *models.NetworkKey
		customer *models.Customer
		wantMin  float64
		wantMax  float64
	}{
		{
			name: "nil network key",
			nk:   nil,
			customer: &models.Customer{
				ID: "test",
			},
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name: "nil customer",
			nk: &models.NetworkKey{
				ExitIP: "203.0.113.1",
			},
			customer: nil,
			wantMin:  0.0,
			wantMax:  0.0,
		},
		{
			name: "matching network key",
			nk: &models.NetworkKey{
				ExitIP:   "203.0.113.1",
				PublicIP: "203.0.113.50",
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true, LatencyMS: 1.0},
					{IP: "203.0.113.1", IsPrivate: false, LatencyMS: 10.0},
				},
				PrivateHops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
				},
			},
			customer: &models.Customer{
				Networks: models.CustomerNetworks{
					ExitIPs:  "203.0.113.1",
					PublicIP: "203.0.113.0/24",
				},
				Metadata: models.CustomerMetadata{
					NetworkSize: "small",
				},
			},
			wantMin: 0.3,
			wantMax: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := fp.AggregateScore(tt.nk, tt.customer)
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("AggregateScore() = %f, want between %f and %f", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCalculateHopPatternScore(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name        string
		nk          *models.NetworkKey
		fingerprint *models.Fingerprint
		want        float64
	}{
		{
			name: "nil network key",
			nk:   nil,
			fingerprint: &models.Fingerprint{
				HopCount: "2-3",
			},
			want: 0.0,
		},
		{
			name: "nil fingerprint",
			nk: &models.NetworkKey{
				Hops: []models.Hop{{IP: "192.168.1.1"}},
			},
			fingerprint: nil,
			want:        0.0,
		},
		{
			name: "hop count mismatch",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1"},
					{IP: "192.168.1.2"},
					{IP: "192.168.1.3"},
					{IP: "192.168.1.4"},
					{IP: "192.168.1.5"},
				},
			},
			fingerprint: &models.Fingerprint{
				HopCount: "2-3",
			},
			want: 0.0,
		},
		{
			name: "matching hop count",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
					{IP: "203.0.113.1", IsPrivate: false},
				},
			},
			fingerprint: &models.Fingerprint{
				HopCount: "2",
			},
			want: 1.0,
		},
		{
			name: "matching private hop pattern",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
					{IP: "203.0.113.1", IsPrivate: false},
				},
			},
			fingerprint: &models.Fingerprint{
				PrivateHopPattern: []models.HopPattern{
					{Position: 1, IPPattern: "192.168.1.1"},
				},
			},
			want: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.calculateHopPatternScore(tt.nk, tt.fingerprint)
			if got != tt.want {
				t.Errorf("calculateHopPatternScore() = %f, want %f", got, tt.want)
			}
		})
	}
}

func TestCalculateLatencyScore(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name        string
		nk          *models.NetworkKey
		fingerprint *models.Fingerprint
		wantMin     float64
		wantMax     float64
	}{
		{
			name: "nil network key",
			nk:   nil,
			fingerprint: &models.Fingerprint{
				LatencyProfile: models.LatencyProfile{
					FirstHop: "1-2ms",
				},
			},
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name: "nil fingerprint",
			nk: &models.NetworkKey{
				Hops: []models.Hop{{IP: "192.168.1.1", LatencyMS: 1.0}},
			},
			fingerprint: nil,
			wantMin:     0.0,
			wantMax:     0.0,
		},
		{
			name: "empty hops",
			nk: &models.NetworkKey{
				Hops: []models.Hop{},
			},
			fingerprint: &models.Fingerprint{
				LatencyProfile: models.LatencyProfile{
					FirstHop: "1-2ms",
				},
			},
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name: "first hop latency match",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", LatencyMS: 1.5},
					{IP: "203.0.113.1", LatencyMS: 10.0},
				},
			},
			fingerprint: &models.Fingerprint{
				LatencyProfile: models.LatencyProfile{
					FirstHop: "1-2ms",
				},
			},
			wantMin: 0.99,
			wantMax: 1.0,
		},
		{
			name: "exit hop latency match",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", LatencyMS: 1.0},
					{IP: "203.0.113.1", LatencyMS: 10.0},
				},
			},
			fingerprint: &models.Fingerprint{
				LatencyProfile: models.LatencyProfile{
					ExitHop: "9-11ms",
				},
			},
			wantMin: 0.99,
			wantMax: 1.0,
		},
		{
			name: "total time match",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", LatencyMS: 5.0},
					{IP: "203.0.113.1", LatencyMS: 10.0},
				},
			},
			fingerprint: &models.Fingerprint{
				LatencyProfile: models.LatencyProfile{
					TotalTime: "14-16ms",
				},
			},
			wantMin: 0.99,
			wantMax: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.calculateLatencyScore(tt.nk, tt.fingerprint)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("calculateLatencyScore() = %f, want between %f and %f", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCalculateNetworkSizeScore(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name     string
		nk       *models.NetworkKey
		customer *models.Customer
		want     float64
	}{
		{
			name:     "nil network key",
			nk:       nil,
			customer: &models.Customer{},
			want:     0.0,
		},
		{
			name:     "nil customer",
			nk:       &models.NetworkKey{},
			customer: nil,
			want:     0.0,
		},
		{
			name: "small network match",
			nk: &models.NetworkKey{
				PrivateHops: []models.Hop{
					{IP: "192.168.1.1"},
				},
			},
			customer: &models.Customer{
				Metadata: models.CustomerMetadata{
					NetworkSize: "small",
				},
			},
			want: 1.0,
		},
		{
			name: "medium network match",
			nk: &models.NetworkKey{
				PrivateHops: []models.Hop{
					{IP: "192.168.1.1"},
					{IP: "192.168.1.2"},
					{IP: "192.168.1.3"},
				},
			},
			customer: &models.Customer{
				Metadata: models.CustomerMetadata{
					NetworkSize: "medium",
				},
			},
			want: 1.0,
		},
		{
			name: "large network match",
			nk: &models.NetworkKey{
				PrivateHops: make([]models.Hop, 5),
			},
			customer: &models.Customer{
				Metadata: models.CustomerMetadata{
					NetworkSize: "large",
				},
			},
			want: 1.0,
		},
		{
			name: "size mismatch",
			nk: &models.NetworkKey{
				PrivateHops: make([]models.Hop, 5),
			},
			customer: &models.Customer{
				Metadata: models.CustomerMetadata{
					NetworkSize: "small",
				},
			},
			want: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.calculateNetworkSizeScore(tt.nk, tt.customer)
			if got != tt.want {
				t.Errorf("calculateNetworkSizeScore() = %f, want %f", got, tt.want)
			}
		})
	}
}

func TestMatchPatternOnHop(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name        string
		hops        []models.Hop
		pattern     models.HopPattern
		requirePriv bool
		want        bool
	}{
		{
			name: "match at position 1",
			hops: []models.Hop{
				{IP: "192.168.1.1", IsPrivate: true},
				{IP: "203.0.113.1", IsPrivate: false},
			},
			pattern: models.HopPattern{
				Position:  1,
				IPPattern: "192.168.1.1",
			},
			requirePriv: true,
			want:        true,
		},
		{
			name: "match at last position",
			hops: []models.Hop{
				{IP: "192.168.1.1", IsPrivate: true},
				{IP: "203.0.113.1", IsPrivate: false},
			},
			pattern: models.HopPattern{
				Position:  "last",
				IPPattern: "203.0.113.1",
			},
			requirePriv: false,
			want:        true,
		},
		{
			name: "private requirement mismatch",
			hops: []models.Hop{
				{IP: "192.168.1.1", IsPrivate: true},
			},
			pattern: models.HopPattern{
				Position:  1,
				IPPattern: "192.168.1.1",
			},
			requirePriv: false,
			want:        false,
		},
		{
			name: "position out of range",
			hops: []models.Hop{
				{IP: "192.168.1.1", IsPrivate: true},
			},
			pattern: models.HopPattern{
				Position:  5,
				IPPattern: "192.168.1.1",
			},
			requirePriv: true,
			want:        false,
		},
		{
			name:    "empty hops",
			hops:    []models.Hop{},
			pattern: models.HopPattern{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPatternOnHop(tt.hops, tt.pattern, tt.requirePriv, fp)
			if got != tt.want {
				t.Errorf("matchPatternOnHop() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLastPosition(t *testing.T) {
	tests := []struct {
		name string
		pos  interface{}
		want bool
	}{
		{
			name: "string last",
			pos:  "last",
			want: true,
		},
		{
			name: "string LAST",
			pos:  "LAST",
			want: true,
		},
		{
			name: "string Last",
			pos:  "Last",
			want: true,
		},
		{
			name: "number",
			pos:  1,
			want: false,
		},
		{
			name: "other string",
			pos:  "first",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLastPosition(tt.pos)
			if got != tt.want {
				t.Errorf("isLastPosition(%v) = %v, want %v", tt.pos, got, tt.want)
			}
		})
	}
}

func TestPositionIndex(t *testing.T) {
	tests := []struct {
		name string
		pos  interface{}
		want int
	}{
		{
			name: "int",
			pos:  5,
			want: 5,
		},
		{
			name: "int64",
			pos:  int64(10),
			want: 10,
		},
		{
			name: "float64",
			pos:  float64(3.0),
			want: 3,
		},
		{
			name: "string number",
			pos:  "7",
			want: 7,
		},
		{
			name: "string with spaces",
			pos:  "  9  ",
			want: 9,
		},
		{
			name: "invalid string",
			pos:  "not-a-number",
			want: 0,
		},
		{
			name: "unknown type",
			pos:  true,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := positionIndex(tt.pos)
			if got != tt.want {
				t.Errorf("positionIndex(%v) = %d, want %d", tt.pos, got, tt.want)
			}
		})
	}
}

func TestParseTracerouteOutput(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name    string
		output  []byte
		wantLen int
	}{
		{
			name:    "nil fingerprinter",
			output:  []byte("1  192.168.1.1  1.234 ms"),
			wantLen: 0,
		},
		{
			name:    "empty output",
			output:  []byte(""),
			wantLen: 0,
		},
		{
			name: "valid traceroute",
			output: []byte(`traceroute to 1.1.1.1
 1  192.168.1.1  1.234 ms  1.456 ms  1.678 ms
 2  10.0.0.1  5.123 ms  5.234 ms  5.345 ms
 3  203.0.113.1  10.500 ms  10.600 ms  10.700 ms
`),
			wantLen: 3,
		},
		{
			name: "traceroute with stars",
			output: []byte(`traceroute to 1.1.1.1
 1  192.168.1.1  1.234 ms
 2  *  * *
 3  203.0.113.1  10.500 ms
`),
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []models.Hop
			if tt.name == "nil fingerprinter" {
				got = parseTracerouteOutput(tt.output, nil)
			} else {
				got = parseTracerouteOutput(tt.output, fp)
			}
			if len(got) != tt.wantLen {
				t.Errorf("parseTracerouteOutput() returned %d hops, want %d", len(got), tt.wantLen)
			}
			if tt.wantLen > 0 && len(got) > 0 {
				for i, hop := range got {
					if hop.IP == "" {
						t.Errorf("hop[%d].IP is empty", i)
					}
				}
			}
		})
	}
}

func TestGenerateNetworkKey(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name     string
		hops     []models.Hop
		target   string
		publicIP string
		raw      string
		wantNil  bool
	}{
		{
			name: "valid hops",
			hops: []models.Hop{
				{IP: "192.168.1.1", IsPrivate: true, LatencyMS: 1.0},
				{IP: "203.0.113.1", IsPrivate: false, LatencyMS: 10.0},
			},
			target:   "1.1.1.1",
			publicIP: "203.0.113.50",
			raw:      "traceroute output",
			wantNil:  false,
		},
		{
			name:     "empty hops",
			hops:     []models.Hop{},
			target:   "1.1.1.1",
			publicIP: "",
			raw:      "",
			wantNil:  false,
		},
		{
			name: "nil fingerprinter",
			hops: []models.Hop{
				{IP: "192.168.1.1", IsPrivate: true},
			},
			target:  "1.1.1.1",
			raw:     "test",
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *models.NetworkKey
			if tt.name == "nil fingerprinter" {
				got = generateNetworkKey(tt.hops, tt.target, tt.publicIP, tt.raw, nil)
			} else {
				got = generateNetworkKey(tt.hops, tt.target, tt.publicIP, tt.raw, fp)
			}

			if (got == nil) != tt.wantNil {
				t.Errorf("generateNetworkKey() = %v, wantNil %v", got, tt.wantNil)
				return
			}

			if !tt.wantNil {
				if got.Target != tt.target {
					t.Errorf("NetworkKey.Target = %q, want %q", got.Target, tt.target)
				}
				if got.PublicIP != tt.publicIP {
					t.Errorf("NetworkKey.PublicIP = %q, want %q", got.PublicIP, tt.publicIP)
				}
				if got.Raw != tt.raw {
					t.Errorf("NetworkKey.Raw = %q, want %q", got.Raw, tt.raw)
				}
				if got.TotalHops != len(tt.hops) {
					t.Errorf("NetworkKey.TotalHops = %d, want %d", got.TotalHops, len(tt.hops))
				}
				if len(tt.hops) > 0 && got.ExitIP != tt.hops[len(tt.hops)-1].IP {
					t.Errorf("NetworkKey.ExitIP = %q, want %q", got.ExitIP, tt.hops[len(tt.hops)-1].IP)
				}
			}
		})
	}
}

func TestBestFingerprintScores(t *testing.T) {
	fp := NewCustomerFingerprinter("")

	tests := []struct {
		name       string
		nk         *models.NetworkKey
		customer   *models.Customer
		wantHopMin float64
		wantHopMax float64
	}{
		{
			name: "no fingerprints",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true},
				},
			},
			customer: &models.Customer{
				Fingerprints: []models.Fingerprint{},
			},
			wantHopMin: 0.0,
			wantHopMax: 0.0,
		},
		{
			name: "single fingerprint",
			nk: &models.NetworkKey{
				Hops: []models.Hop{
					{IP: "192.168.1.1", IsPrivate: true, LatencyMS: 1.0},
				},
			},
			customer: &models.Customer{
				Fingerprints: []models.Fingerprint{
					{
						HopCount: "1",
					},
				},
			},
			wantHopMin: 0.0,
			wantHopMax: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHop, gotLatency := fp.bestFingerprintScores(tt.nk, tt.customer)
			if gotHop < tt.wantHopMin || gotHop > tt.wantHopMax {
				t.Errorf("bestFingerprintScores() hop = %f, want between %f and %f", gotHop, tt.wantHopMin, tt.wantHopMax)
			}
			if gotLatency < 0 || gotLatency > 1 {
				t.Errorf("bestFingerprintScores() latency = %f, want 0.0-1.0", gotLatency)
			}
		})
	}
}

func TestLoadTracerouteHistory_ErrorCases(t *testing.T) {
	tempDir := t.TempDir()

	fp := NewCustomerFingerprinter("")
	fp.TraceroutesPath = filepath.Join(tempDir, "subdir", "nonexistent", "traceroutes.json")

	fp.loadTracerouteHistory()

	if fp.CustomerTraceroutes == nil {
		t.Error("CustomerTraceroutes should not be nil after failed load")
	}
}
