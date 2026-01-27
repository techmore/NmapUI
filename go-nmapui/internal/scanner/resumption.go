package scanner

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ScanMetadata represents the metadata stored with each scan
type ScanMetadata struct {
	Timestamp    string                 `json:"timestamp"`
	CustomerID   string                 `json:"customer_id"`
	CustomerName string                 `json:"customer_name"`
	Target       string                 `json:"target"`
	NetworkKey   map[string]interface{} `json:"network_key"`
}

// ResumableScan contains information about a scan that can be resumed
type ResumableScan struct {
	XMLPath     string
	Metadata    ScanMetadata
	ScanTime    time.Time
	AgeSeconds  int64
	AgeDays     int
	TotalHosts  int
	TotalVulns  int
}

// NmapXMLHost represents a host in nmap XML output
type NmapXMLHost struct {
	XMLName   xml.Name          `xml:"host"`
	Status    NmapXMLStatus     `xml:"status"`
	Addresses []NmapXMLAddress  `xml:"address"`
	Hostnames NmapXMLHostnames  `xml:"hostnames"`
	Ports     NmapXMLPorts      `xml:"ports"`
}

type NmapXMLStatus struct {
	State string `xml:"state,attr"`
}

type NmapXMLAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type NmapXMLHostnames struct {
	Hostnames []NmapXMLHostname `xml:"hostname"`
}

type NmapXMLHostname struct {
	Name string `xml:"name,attr"`
}

type NmapXMLPorts struct {
	Ports []NmapXMLPort `xml:"port"`
}

type NmapXMLPort struct {
	PortID   string           `xml:"portid,attr"`
	Protocol string           `xml:"protocol,attr"`
	State    NmapXMLState     `xml:"state"`
	Service  NmapXMLService   `xml:"service"`
	Scripts  []NmapXMLScript  `xml:"script"`
}

type NmapXMLState struct {
	State string `xml:"state,attr"`
}

type NmapXMLService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type NmapXMLScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type NmapXMLRun struct {
	XMLName xml.Name      `xml:"nmaprun"`
	Hosts   []NmapXMLHost `xml:"host"`
}

// ParsedHost represents a host parsed from nmap XML
type ParsedHost struct {
	IP              string                   `json:"ip"`
	Hostname        string                   `json:"hostname"`
	MAC             string                   `json:"mac"`
	Vendor          string                   `json:"vendor"`
	Ports           string                   `json:"ports"`
	Status          string                   `json:"status"`
	Vulnerabilities []map[string]interface{} `json:"vulnerabilities"`
}

// FindMostRecentScan finds the most recent scan for a customer within maxDays
func FindMostRecentScan(scansDir string, customerName string, maxDays int) (*ResumableScan, error) {
	if customerName == "" {
		customerName = "Unknown"
	}

	cutoffTime := time.Now().AddDate(0, 0, -maxDays)
	var recentScans []ResumableScan

	// Search in customer's scan directory
	customerDir := filepath.Join(scansDir, customerName)
	if err := searchScansInDir(customerDir, cutoffTime, &recentScans); err != nil {
		// Directory may not exist, which is fine
	}

	// Also search in Unknown_Network as fallback
	unknownDir := filepath.Join(scansDir, "Unknown_Network")
	if customerName != "Unknown_Network" {
		if err := searchScansInDir(unknownDir, cutoffTime, &recentScans); err != nil {
			// Directory may not exist, which is fine
		}
	}

	if len(recentScans) == 0 {
		return nil, nil
	}

	// Sort by scan time, most recent first
	sort.Slice(recentScans, func(i, j int) bool {
		return recentScans[i].ScanTime.After(recentScans[j].ScanTime)
	})

	return &recentScans[0], nil
}

func searchScansInDir(baseDir string, cutoffTime time.Time, results *[]ResumableScan) error {
	dateDirs, err := os.ReadDir(baseDir)
	if err != nil {
		return err
	}

	for _, dateDir := range dateDirs {
		if !dateDir.IsDir() {
			continue
		}

		datePath := filepath.Join(baseDir, dateDir.Name())
		scanDirs, err := os.ReadDir(datePath)
		if err != nil {
			continue
		}

		for _, scanDir := range scanDirs {
			if !scanDir.IsDir() {
				continue
			}

			scanPath := filepath.Join(datePath, scanDir.Name())
			metadataPath := filepath.Join(scanPath, "metadata.json")
			xmlPath := filepath.Join(scanPath, "scan.xml")

			// Check if both files exist
			if _, err := os.Stat(metadataPath); err != nil {
				continue
			}
			if _, err := os.Stat(xmlPath); err != nil {
				continue
			}

			// Load metadata
			metadataData, err := os.ReadFile(metadataPath)
			if err != nil {
				continue
			}

			var metadata ScanMetadata
			if err := json.Unmarshal(metadataData, &metadata); err != nil {
				continue
			}

			if metadata.Timestamp == "" {
				continue
			}

			scanTime, err := time.Parse(time.RFC3339, metadata.Timestamp)
			if err != nil {
				// Try alternative formats
				scanTime, err = time.Parse("2006-01-02T15:04:05", metadata.Timestamp)
				if err != nil {
					continue
				}
			}

			if scanTime.Before(cutoffTime) {
				continue
			}

			// Parse XML for host count
			hosts, err := ParseNmapXML(xmlPath)
			if err != nil {
				continue
			}

			totalVulns := 0
			for _, host := range hosts {
				totalVulns += len(host.Vulnerabilities)
			}

			ageSeconds := int64(time.Since(scanTime).Seconds())
			ageDays := int(ageSeconds / (24 * 3600))

			*results = append(*results, ResumableScan{
				XMLPath:    xmlPath,
				Metadata:   metadata,
				ScanTime:   scanTime,
				AgeSeconds: ageSeconds,
				AgeDays:    ageDays,
				TotalHosts: len(hosts),
				TotalVulns: totalVulns,
			})
		}
	}

	return nil
}

// ParseNmapXML parses an nmap XML file and returns host information
func ParseNmapXML(xmlPath string) ([]ParsedHost, error) {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, err
	}

	var nmapRun NmapXMLRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		return nil, err
	}

	var hosts []ParsedHost

	for _, xmlHost := range nmapRun.Hosts {
		if xmlHost.Status.State != "up" {
			continue
		}

		host := ParsedHost{
			Status:          "up",
			Vulnerabilities: []map[string]interface{}{},
		}

		// Extract addresses
		for _, addr := range xmlHost.Addresses {
			switch addr.AddrType {
			case "ipv4":
				host.IP = addr.Addr
			case "mac":
				host.MAC = addr.Addr
				host.Vendor = addr.Vendor
			}
		}

		// Extract hostname
		if len(xmlHost.Hostnames.Hostnames) > 0 {
			host.Hostname = xmlHost.Hostnames.Hostnames[0].Name
		}

		// Extract ports and vulnerabilities
		var openPorts []string
		for _, port := range xmlHost.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			portStr := port.PortID
			if port.Service.Name != "" {
				portStr += " (" + port.Service.Name + ")"
			}
			openPorts = append(openPorts, portStr)

			// Check for vulners script output
			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					// Parse CVEs from vulners output
					vulns := parseVulnersOutput(script.Output, port.PortID, port.Service.Name)
					host.Vulnerabilities = append(host.Vulnerabilities, vulns...)
				}
			}
		}

		if len(openPorts) > 0 {
			host.Ports = joinPorts(openPorts)
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

func parseVulnersOutput(output string, port string, service string) []map[string]interface{} {
	// Simple CVE extraction from vulners output
	// Format is typically "CVE-XXXX-XXXXX\t\tX.X\t\thttps://..."
	var vulns []map[string]interface{}

	// This is a simplified parser - the actual vulners output format may vary
	// For now, we just identify CVE patterns
	lines := splitLines(output)
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		// Look for CVE pattern
		if len(line) >= 13 && line[0:4] == "CVE-" {
			parts := splitTabs(line)
			if len(parts) >= 1 {
				vuln := map[string]interface{}{
					"cve_id":    parts[0],
					"port":      port,
					"service":   service,
					"type":      "cve",
					"is_exploit": false,
				}
				if len(parts) >= 2 {
					vuln["cvss"] = parts[1]
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitTabs(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\t' {
			if i > start {
				parts = append(parts, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}

func joinPorts(ports []string) string {
	if len(ports) == 0 {
		return ""
	}
	result := ports[0]
	for i := 1; i < len(ports); i++ {
		result += ", " + ports[i]
	}
	return result
}
