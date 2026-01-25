package scanner

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/techmore/nmapui/internal/models"
)

func TestEstimateHosts(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   int
	}{
		{"single IP", "192.168.1.1", 1},
		{"CIDR /24", "192.168.1.0/24", 256},
		{"CIDR /16", "10.0.0.0/16", 65536},
		{"CIDR /32", "192.168.1.1/32", 1},
		{"CIDR /8", "10.0.0.0/8", 16777216},
		{"IP range", "192.168.1.1-192.168.1.10", 10},
		{"IP range reversed", "192.168.1.10-192.168.1.1", 10},
		{"hostname", "example.com", 254},
		{"invalid CIDR", "192.168.1.0/99", 254},
		{"invalid range", "not-an-ip-range", 254},
		{"IPv6 CIDR", "2001:db8::/32", 1},
		{"IPv6 range", "2001:db8::1-2001:db8::10", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateHosts(tt.target)
			if got != tt.want {
				t.Errorf("estimateHosts(%q) = %d, want %d", tt.target, got, tt.want)
			}
		})
	}
}

func TestEstimateTargets(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		want    int
	}{
		{
			name:    "single IP",
			targets: []string{"192.168.1.1"},
			want:    1,
		},
		{
			name:    "multiple IPs",
			targets: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			want:    3,
		},
		{
			name:    "CIDR and IP",
			targets: []string{"192.168.1.0/24", "10.0.0.1"},
			want:    257,
		},
		{
			name:    "empty targets",
			targets: []string{},
			want:    1,
		},
		{
			name:    "range",
			targets: []string{"192.168.1.1-192.168.1.50"},
			want:    50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateTargets(tt.targets)
			if got != tt.want {
				t.Errorf("estimateTargets() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetAdaptiveScanConfig(t *testing.T) {
	engine := NewScanEngine(NewNmapScanner("nmap"), nil, 10)

	tests := []struct {
		name         string
		targets      []string
		wantTiming   string
		wantTopPorts int
		wantScanType string
		wantMaxConc  int
	}{
		{
			name:         "small network (10 hosts)",
			targets:      []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			wantTiming:   "aggressive",
			wantTopPorts: 1000,
			wantScanType: "fast",
			wantMaxConc:  5,
		},
		{
			name:         "medium network (100 hosts)",
			targets:      []string{"192.168.1.0/25"},
			wantTiming:   "normal",
			wantTopPorts: 500,
			wantScanType: "balanced",
			wantMaxConc:  8,
		},
		{
			name:         "large network (/24)",
			targets:      []string{"192.168.1.0/24"},
			wantTiming:   "polite",
			wantTopPorts: 200,
			wantScanType: "thorough",
			wantMaxConc:  10,
		},
		{
			name:         "very large network (500 hosts)",
			targets:      []string{"10.0.0.0/23"},
			wantTiming:   "polite",
			wantTopPorts: 200,
			wantScanType: "thorough",
			wantMaxConc:  10,
		},
		{
			name:         "massive network (/16)",
			targets:      []string{"10.0.0.0/16"},
			wantTiming:   "polite",
			wantTopPorts: 100,
			wantScanType: "conservative",
			wantMaxConc:  10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := engine.GetAdaptiveScanConfig(tt.targets)
			if config.TimingProfile != tt.wantTiming {
				t.Errorf("timing = %q, want %q", config.TimingProfile, tt.wantTiming)
			}
			if config.TopPorts != tt.wantTopPorts {
				t.Errorf("top_ports = %d, want %d", config.TopPorts, tt.wantTopPorts)
			}
			if config.ScanType != tt.wantScanType {
				t.Errorf("scan_type = %q, want %q", config.ScanType, tt.wantScanType)
			}
			if config.MaxConcurrent != tt.wantMaxConc {
				t.Errorf("max_concurrent = %d, want %d", config.MaxConcurrent, tt.wantMaxConc)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{"under 1 minute", 45 * time.Second, "45s"},
		{"exactly 1 minute", 60 * time.Second, "1m 0s"},
		{"1 minute 30 seconds", 90 * time.Second, "1m 30s"},
		{"under 1 hour", 45 * time.Minute, "45m 0s"},
		{"exactly 1 hour", 1 * time.Hour, "1h 0m"},
		{"1 hour 30 minutes", 90 * time.Minute, "1h 30m"},
		{"multiple hours", 3*time.Hour + 15*time.Minute, "3h 15m"},
		{"zero duration", 0, "0s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.duration)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, got, tt.want)
			}
		})
	}
}

func TestCountSuccessful(t *testing.T) {
	tests := []struct {
		name  string
		hosts []models.Host
		want  int
	}{
		{
			name: "all successful",
			hosts: []models.Host{
				{IP: "192.168.1.1", Status: "up"},
				{IP: "192.168.1.2", Status: "up"},
			},
			want: 2,
		},
		{
			name: "mixed status",
			hosts: []models.Host{
				{IP: "192.168.1.1", Status: "up"},
				{IP: "192.168.1.2", Status: "error"},
				{IP: "192.168.1.3", Status: "down"},
			},
			want: 2,
		},
		{
			name: "all errors",
			hosts: []models.Host{
				{IP: "192.168.1.1", Status: "error"},
				{IP: "192.168.1.2", Status: "error"},
			},
			want: 0,
		},
		{
			name:  "empty list",
			hosts: []models.Host{},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countSuccessful(tt.hosts)
			if got != tt.want {
				t.Errorf("countSuccessful() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{"a smaller", 5, 10, 5},
		{"b smaller", 10, 5, 5},
		{"equal", 7, 7, 7},
		{"negative", -5, 3, -5},
		{"both negative", -10, -3, -10},
		{"zero", 0, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := minInt(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIPv4ToUint32(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want uint32
	}{
		{"zero", "0.0.0.0", 0},
		{"localhost", "127.0.0.1", 2130706433},
		{"class C", "192.168.1.1", 3232235777},
		{"class A", "10.0.0.1", 167772161},
		{"broadcast", "255.255.255.255", 4294967295},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.ip)
			if err != nil {
				t.Fatalf("failed to parse IP %q: %v", tt.ip, err)
			}
			got := ipv4ToUint32(addr)
			if got != tt.want {
				t.Errorf("ipv4ToUint32(%q) = %d, want %d", tt.ip, got, tt.want)
			}
		})
	}
}

func TestNewScanEngine(t *testing.T) {
	scanner := NewNmapScanner("nmap")

	tests := []struct {
		name          string
		maxConcurrent int
		want          int
	}{
		{"positive value", 5, 5},
		{"zero defaults to 10", 0, 10},
		{"negative defaults to 10", -5, 10},
		{"large value", 100, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewScanEngine(scanner, nil, tt.maxConcurrent)
			if engine == nil {
				t.Fatal("NewScanEngine returned nil")
			}
			if engine.maxConcurrent != tt.want {
				t.Errorf("maxConcurrent = %d, want %d", engine.maxConcurrent, tt.want)
			}
			if engine.scanner != scanner {
				t.Error("scanner not set correctly")
			}
		})
	}
}

type mockPublisher struct {
	events []string
}

func (m *mockPublisher) Publish(event string, payload any) {
	m.events = append(m.events, event)
}

func TestScanEngine_QuickScan(t *testing.T) {
	scanner := NewNmapScanner("nmap")
	publisher := &mockPublisher{}
	engine := NewScanEngine(scanner, publisher, 5)

	ctx := context.Background()
	_, err := engine.QuickScan(ctx, "127.0.0.1")

	if err != nil {
		t.Logf("QuickScan error (expected if nmap not available): %v", err)
	}

	if len(publisher.events) < 1 {
		t.Error("expected at least 1 event to be published")
	}

	foundStart := false
	for _, event := range publisher.events {
		if event == "quick_scan_start" {
			foundStart = true
			break
		}
	}
	if !foundStart {
		t.Error("expected 'quick_scan_start' event to be published")
	}
}

func TestScanEngine_ARPScan(t *testing.T) {
	scanner := NewNmapScanner("nmap")
	publisher := &mockPublisher{}
	engine := NewScanEngine(scanner, publisher, 5)

	ctx := context.Background()
	_, err := engine.ARPScan(ctx, "192.168.1.0/30")

	if err != nil {
		t.Logf("ARPScan error (expected if nmap not available): %v", err)
	}

	if len(publisher.events) < 1 {
		t.Error("expected at least 1 event to be published")
	}

	foundStart := false
	for _, event := range publisher.events {
		if event == "arp_scan_start" {
			foundStart = true
			break
		}
	}
	if !foundStart {
		t.Error("expected 'arp_scan_start' event to be published")
	}
}

func TestScanEngine_DeepScan_EmptyTargets(t *testing.T) {
	scanner := NewNmapScanner("nmap")
	engine := NewScanEngine(scanner, nil, 5)

	ctx := context.Background()
	result, err := engine.DeepScan(ctx, []string{})

	if err != nil {
		t.Errorf("DeepScan with empty targets should not error, got: %v", err)
	}

	if result.TotalHosts != 0 {
		t.Errorf("TotalHosts = %d, want 0", result.TotalHosts)
	}

	if len(result.Hosts) != 0 {
		t.Errorf("len(Hosts) = %d, want 0", len(result.Hosts))
	}
}

func TestScanEngine_DeepScan_SingleTarget(t *testing.T) {
	scanner := NewNmapScanner("nmap")
	publisher := &mockPublisher{}
	engine := NewScanEngine(scanner, publisher, 5)

	ctx := context.Background()
	result, err := engine.DeepScan(ctx, []string{"127.0.0.1"})

	if err != nil {
		t.Logf("DeepScan error (expected if nmap not available): %v", err)
	}

	if result.ScanID == "" {
		t.Error("ScanID should not be empty")
	}

	if result.TotalHosts != 1 {
		t.Errorf("TotalHosts = %d, want 1", result.TotalHosts)
	}

	foundStart := false
	for _, event := range publisher.events {
		if event == "deep_scan_start" {
			foundStart = true
			break
		}
	}
	if !foundStart {
		t.Error("expected 'deep_scan_start' event to be published")
	}
}

func TestScanEngine_Emit_NilHub(t *testing.T) {
	scanner := NewNmapScanner("nmap")
	engine := NewScanEngine(scanner, nil, 5)

	engine.emit("test_event", map[string]any{"key": "value"})
}

func TestScanEngine_ScanRate(t *testing.T) {
	scanner := NewNmapScanner("nmap")
	engine := NewScanEngine(scanner, nil, 5)

	engine.scanStartTime = time.Now().Add(-1 * time.Second)
	engine.hostsScanned = 10

	rate := engine.scanRate()
	if rate <= 0 {
		t.Errorf("scanRate() = %f, want > 0", rate)
	}
	if rate > 100 {
		t.Errorf("scanRate() = %f, seems too high", rate)
	}
}

func TestScanEngine_ScanRate_ZeroHosts(t *testing.T) {
	scanner := NewNmapScanner("nmap")
	engine := NewScanEngine(scanner, nil, 5)

	rate := engine.scanRate()
	if rate != 0 {
		t.Errorf("scanRate() with zero hosts = %f, want 0", rate)
	}
}

func BenchmarkEstimateHosts(b *testing.B) {
	targets := []string{
		"192.168.1.1",
		"10.0.0.0/24",
		"192.168.1.1-192.168.1.100",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, target := range targets {
			estimateHosts(target)
		}
	}
}

func BenchmarkFormatDuration(b *testing.B) {
	duration := 3*time.Hour + 25*time.Minute + 45*time.Second
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatDuration(duration)
	}
}
