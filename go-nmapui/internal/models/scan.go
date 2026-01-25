package models

import "time"

type ScanConfig struct {
	TimingProfile string        `json:"timing_profile"`
	TopPorts      int           `json:"top_ports"`
	Timeout       time.Duration `json:"timeout"`
	MaxConcurrent int           `json:"max_concurrent"`
	ScanType      string        `json:"scan_type"`
}

type ScanResult struct {
	ScanID       string    `json:"scan_id"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	Hosts        []Host    `json:"hosts"`
	TotalHosts   int       `json:"total_hosts"`
	HostsScanned int       `json:"hosts_scanned"`
	Errors       []string  `json:"errors,omitempty"`
}

type Host struct {
	IP        string        `json:"ip"`
	Status    string        `json:"status"`
	Hostnames []Hostname    `json:"hostnames,omitempty"`
	Ports     []Port        `json:"ports,omitempty"`
	OS        *OSInfo       `json:"os_info,omitempty"`
	CVEs      []CVE         `json:"cves,omitempty"`
	ScanTime  time.Duration `json:"scan_time,omitempty"`
	Error     string        `json:"error,omitempty"`
}

type Hostname struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type OSInfo struct {
	Name     string `json:"name"`
	Accuracy int    `json:"accuracy,omitempty"`
}

type Port struct {
	Port     string  `json:"port"`
	Protocol string  `json:"protocol"`
	State    string  `json:"state"`
	Service  Service `json:"service"`
}

type Service struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Product   string `json:"product,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`
}

type CVE struct {
	ID     string  `json:"id"`
	Score  float64 `json:"score,omitempty"`
	URL    string  `json:"url,omitempty"`
	Source string  `json:"source,omitempty"`
}
