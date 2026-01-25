package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/techmore/nmapui/internal/models"
)

func TestMapTimingProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		want    nmap.Timing
	}{
		{"aggressive", "aggressive", nmap.TimingAggressive},
		{"fast", "fast", nmap.TimingAggressive},
		{"t4", "t4", nmap.TimingAggressive},
		{"normal", "normal", nmap.TimingNormal},
		{"balanced", "balanced", nmap.TimingNormal},
		{"t3", "t3", nmap.TimingNormal},
		{"polite", "polite", nmap.TimingPolite},
		{"thorough", "thorough", nmap.TimingPolite},
		{"t2", "t2", nmap.TimingPolite},
		{"default", "unknown", nmap.TimingNormal},
		{"empty", "", nmap.TimingNormal},
		{"uppercase", "AGGRESSIVE", nmap.TimingAggressive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapTimingProfile(tt.profile)
			if got != tt.want {
				t.Errorf("mapTimingProfile(%q) = %v, want %v", tt.profile, got, tt.want)
			}
		})
	}
}

func TestSelectIP(t *testing.T) {
	tests := []struct {
		name      string
		addresses []nmap.Address
		want      string
	}{
		{
			name:      "empty addresses",
			addresses: []nmap.Address{},
			want:      "",
		},
		{
			name: "single ipv4",
			addresses: []nmap.Address{
				{Addr: "192.168.1.1", AddrType: "ipv4"},
			},
			want: "192.168.1.1",
		},
		{
			name: "ipv4 and ipv6 - prefer ipv4",
			addresses: []nmap.Address{
				{Addr: "fe80::1", AddrType: "ipv6"},
				{Addr: "192.168.1.1", AddrType: "ipv4"},
			},
			want: "192.168.1.1",
		},
		{
			name: "only ipv6",
			addresses: []nmap.Address{
				{Addr: "fe80::1", AddrType: "ipv6"},
			},
			want: "fe80::1",
		},
		{
			name: "multiple ipv4 - return first",
			addresses: []nmap.Address{
				{Addr: "192.168.1.1", AddrType: "ipv4"},
				{Addr: "10.0.0.1", AddrType: "ipv4"},
			},
			want: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectIP(tt.addresses)
			if got != tt.want {
				t.Errorf("selectIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapHostnames(t *testing.T) {
	tests := []struct {
		name      string
		hostnames []nmap.Hostname
		want      []models.Hostname
	}{
		{
			name:      "nil hostnames",
			hostnames: nil,
			want:      nil,
		},
		{
			name:      "empty hostnames",
			hostnames: []nmap.Hostname{},
			want:      nil,
		},
		{
			name: "single hostname",
			hostnames: []nmap.Hostname{
				{Name: "example.com", Type: "PTR"},
			},
			want: []models.Hostname{
				{Name: "example.com", Type: "PTR"},
			},
		},
		{
			name: "multiple hostnames",
			hostnames: []nmap.Hostname{
				{Name: "example.com", Type: "PTR"},
				{Name: "www.example.com", Type: "user"},
			},
			want: []models.Hostname{
				{Name: "example.com", Type: "PTR"},
				{Name: "www.example.com", Type: "user"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapHostnames(tt.hostnames)
			if len(got) != len(tt.want) {
				t.Errorf("mapHostnames() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i].Name != tt.want[i].Name || got[i].Type != tt.want[i].Type {
					t.Errorf("mapHostnames()[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMapPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []nmap.Port
		want  []models.Port
	}{
		{
			name:  "nil ports",
			ports: nil,
			want:  nil,
		},
		{
			name:  "empty ports",
			ports: []nmap.Port{},
			want:  nil,
		},
		{
			name: "single port",
			ports: []nmap.Port{
				{
					ID:       80,
					Protocol: "tcp",
					State:    nmap.State{State: "open"},
					Service: nmap.Service{
						Name:    "http",
						Product: "nginx",
						Version: "1.18.0",
					},
				},
			},
			want: []models.Port{
				{
					Port:     "80",
					Protocol: "tcp",
					State:    "open",
					Service: models.Service{
						Name:    "http",
						Product: "nginx",
						Version: "1.18.0",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapPorts(tt.ports)
			if len(got) != len(tt.want) {
				t.Errorf("mapPorts() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i].Port != tt.want[i].Port {
					t.Errorf("mapPorts()[%d].Port = %q, want %q", i, got[i].Port, tt.want[i].Port)
				}
			}
		})
	}
}

func TestMapOS(t *testing.T) {
	tests := []struct {
		name   string
		osInfo nmap.OS
		want   *models.OSInfo
	}{
		{
			name:   "no matches",
			osInfo: nmap.OS{Matches: []nmap.OSMatch{}},
			want:   nil,
		},
		{
			name: "single match",
			osInfo: nmap.OS{
				Matches: []nmap.OSMatch{
					{Name: "Linux 5.4", Accuracy: 95},
				},
			},
			want: &models.OSInfo{
				Name:     "Linux 5.4",
				Accuracy: 95,
			},
		},
		{
			name: "multiple matches - return first",
			osInfo: nmap.OS{
				Matches: []nmap.OSMatch{
					{Name: "Linux 5.4", Accuracy: 95},
					{Name: "Linux 5.3", Accuracy: 90},
				},
			},
			want: &models.OSInfo{
				Name:     "Linux 5.4",
				Accuracy: 95,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapOS(tt.osInfo)
			if tt.want == nil {
				if got != nil {
					t.Errorf("mapOS() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Errorf("mapOS() = nil, want %+v", tt.want)
				return
			}
			if got.Name != tt.want.Name || got.Accuracy != tt.want.Accuracy {
				t.Errorf("mapOS() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractCVEsFromScripts(t *testing.T) {
	tests := []struct {
		name    string
		scripts []nmap.Script
		want    int // number of CVEs expected
	}{
		{
			name:    "no scripts",
			scripts: nil,
			want:    0,
		},
		{
			name: "non-vulners script",
			scripts: []nmap.Script{
				{ID: "http-title", Output: "Welcome Page"},
			},
			want: 0,
		},
		{
			name: "vulners script with CVEs",
			scripts: []nmap.Script{
				{
					ID:     "vulners",
					Output: "CVE-2021-1234\nCVE-2021-5678",
				},
			},
			want: 2,
		},
		{
			name: "vulners script with duplicate CVEs",
			scripts: []nmap.Script{
				{
					ID:     "vulners",
					Output: "CVE-2021-1234\nCVE-2021-1234",
				},
			},
			want: 1,
		},
		{
			name: "vulners script with CVE and score",
			scripts: []nmap.Script{
				{
					ID:     "vulners",
					Output: "CVE-2021-1234 7.5 High",
				},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCVEsFromScripts(tt.scripts)
			if len(got) != tt.want {
				t.Errorf("extractCVEsFromScripts() returned %d CVEs, want %d", len(got), tt.want)
			}
			for _, cve := range got {
				if cve.Source != "vulners" {
					t.Errorf("CVE source = %q, want 'vulners'", cve.Source)
				}
				if cve.URL == "" {
					t.Error("CVE URL is empty")
				}
			}
		})
	}
}

func TestMapHosts(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []nmap.Host
		filterUp bool
		want     int
	}{
		{
			name:     "empty hosts",
			hosts:    []nmap.Host{},
			filterUp: false,
			want:     0,
		},
		{
			name: "single up host - filter up",
			hosts: []nmap.Host{
				{
					Status:    nmap.Status{State: "up"},
					Addresses: []nmap.Address{{Addr: "192.168.1.1", AddrType: "ipv4"}},
				},
			},
			filterUp: true,
			want:     1,
		},
		{
			name: "single down host - filter up",
			hosts: []nmap.Host{
				{
					Status:    nmap.Status{State: "down"},
					Addresses: []nmap.Address{{Addr: "192.168.1.1", AddrType: "ipv4"}},
				},
			},
			filterUp: true,
			want:     0,
		},
		{
			name: "mixed hosts - no filter",
			hosts: []nmap.Host{
				{
					Status:    nmap.Status{State: "up"},
					Addresses: []nmap.Address{{Addr: "192.168.1.1", AddrType: "ipv4"}},
				},
				{
					Status:    nmap.Status{State: "down"},
					Addresses: []nmap.Address{{Addr: "192.168.1.2", AddrType: "ipv4"}},
				},
			},
			filterUp: false,
			want:     2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapHosts(tt.hosts, tt.filterUp)
			if len(got) != tt.want {
				t.Errorf("mapHosts() returned %d hosts, want %d", len(got), tt.want)
			}
		})
	}
}

func TestWithTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		wantNil bool
	}{
		{
			name:    "zero timeout",
			timeout: 0,
			wantNil: true,
		},
		{
			name:    "negative timeout",
			timeout: -1 * time.Second,
			wantNil: true,
		},
		{
			name:    "positive timeout",
			timeout: 5 * time.Second,
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			newCtx, cancel := withTimeout(ctx, tt.timeout)
			defer cancel()

			if tt.wantNil {
				if newCtx != ctx {
					t.Error("withTimeout() should return original context for zero/negative timeout")
				}
			} else {
				if newCtx == ctx {
					t.Error("withTimeout() should return new context for positive timeout")
				}
			}
		})
	}
}

func TestNewNmapScanner(t *testing.T) {
	tests := []struct {
		name       string
		binaryPath string
	}{
		{
			name:       "default nmap",
			binaryPath: "nmap",
		},
		{
			name:       "custom path",
			binaryPath: "/usr/local/bin/nmap",
		},
		{
			name:       "empty path",
			binaryPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewNmapScanner(tt.binaryPath)
			if scanner == nil {
				t.Fatal("NewNmapScanner() returned nil")
			}
			if scanner.binaryPath != tt.binaryPath {
				t.Errorf("binaryPath = %q, want %q", scanner.binaryPath, tt.binaryPath)
			}
		})
	}
}

// Benchmark tests
func BenchmarkMapTimingProfile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		mapTimingProfile("aggressive")
	}
}

func BenchmarkSelectIP(b *testing.B) {
	addresses := []nmap.Address{
		{Addr: "fe80::1", AddrType: "ipv6"},
		{Addr: "192.168.1.1", AddrType: "ipv4"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selectIP(addresses)
	}
}

func BenchmarkMapHosts(b *testing.B) {
	hosts := []nmap.Host{
		{
			Status:    nmap.Status{State: "up"},
			Addresses: []nmap.Address{{Addr: "192.168.1.1", AddrType: "ipv4"}},
			Ports: []nmap.Port{
				{ID: 80, Protocol: "tcp", State: nmap.State{State: "open"}},
			},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapHosts(hosts, true)
	}
}
