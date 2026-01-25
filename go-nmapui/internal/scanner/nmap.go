package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/techmore/nmapui/internal/models"
)

type NmapScanner struct {
	binaryPath string
}

func NewNmapScanner(binaryPath string) *NmapScanner {
	return &NmapScanner{binaryPath: binaryPath}
}

func (s *NmapScanner) QuickScan(ctx context.Context, target string, timingProfile string) ([]models.Host, error) {
	result, _, err := s.run(ctx,
		nmap.WithTargets(target),
		nmap.WithPingScan(),
		nmap.WithTimingTemplate(mapTimingProfile(timingProfile)),
	)
	if err != nil {
		return nil, err
	}

	return mapHosts(result.Hosts, true), nil
}

func (s *NmapScanner) ARPScan(ctx context.Context, target string, timingProfile string) ([]models.Host, error) {
	result, _, err := s.run(ctx,
		nmap.WithTargets(target),
		nmap.WithPingScan(),
		nmap.WithCustomArguments("-PR"),
		nmap.WithTimingTemplate(mapTimingProfile(timingProfile)),
		nmap.WithSendEthernet(),
	)
	if err != nil {
		return nil, err
	}

	return mapHosts(result.Hosts, true), nil
}

func (s *NmapScanner) DeepScan(ctx context.Context, target string, config models.ScanConfig) (models.Host, error) {
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithSYNScan(),
		nmap.WithTimingTemplate(mapTimingProfile(config.TimingProfile)),
		nmap.WithAggressiveScan(),
		nmap.WithDefaultScript(),
		nmap.WithScripts("vulners"),
	}

	if config.TopPorts > 0 {
		options = append(options, nmap.WithMostCommonPorts(config.TopPorts))
	}

	if config.Timeout > 0 {
		options = append(options, nmap.WithHostTimeout(config.Timeout))
	}

	result, _, err := s.run(ctx, options...)
	if err != nil {
		return models.Host{IP: target, Status: "error", Error: err.Error()}, err
	}

	if len(result.Hosts) == 0 {
		return models.Host{IP: target, Status: "down"}, nil
	}

	host := mapHosts(result.Hosts, false)
	if len(host) == 0 {
		return models.Host{IP: target, Status: "down"}, nil
	}

	return host[0], nil
}

func (s *NmapScanner) run(ctx context.Context, options ...nmap.Option) (*nmap.Run, []string, error) {
	if s.binaryPath != "" {
		options = append(options, nmap.WithBinaryPath(s.binaryPath))
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, nil, err
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, nil, err
	}

	return result, *warnings, nil
}

func mapTimingProfile(profile string) nmap.Timing {
	switch strings.ToLower(profile) {
	case "aggressive", "fast", "t4":
		return nmap.TimingAggressive
	case "normal", "balanced", "t3":
		return nmap.TimingNormal
	case "polite", "thorough", "t2":
		return nmap.TimingPolite
	default:
		return nmap.TimingNormal
	}
}

func mapHosts(hosts []nmap.Host, filterUp bool) []models.Host {
	results := make([]models.Host, 0, len(hosts))
	for _, host := range hosts {
		status := host.Status.State
		if filterUp && status != "up" {
			continue
		}

		ip := selectIP(host.Addresses)
		results = append(results, models.Host{
			IP:        ip,
			Status:    status,
			Hostnames: mapHostnames(host.Hostnames),
			Ports:     mapPorts(host.Ports),
			OS:        mapOS(host.OS),
			CVEs:      extractCVEs(host),
		})
	}
	return results
}

func selectIP(addresses []nmap.Address) string {
	if len(addresses) == 0 {
		return ""
	}

	for _, addr := range addresses {
		if addr.AddrType == "ipv4" {
			return addr.Addr
		}
	}

	return addresses[0].Addr
}

func mapHostnames(hostnames []nmap.Hostname) []models.Hostname {
	if len(hostnames) == 0 {
		return nil
	}

	items := make([]models.Hostname, 0, len(hostnames))
	for _, host := range hostnames {
		items = append(items, models.Hostname{Name: host.Name, Type: host.Type})
	}
	return items
}

func mapPorts(ports []nmap.Port) []models.Port {
	if len(ports) == 0 {
		return nil
	}

	items := make([]models.Port, 0, len(ports))
	for _, port := range ports {
		items = append(items, models.Port{
			Port:     fmt.Sprintf("%d", port.ID),
			Protocol: port.Protocol,
			State:    port.State.State,
			Service: models.Service{
				Name:      port.Service.Name,
				Version:   port.Service.Version,
				Product:   port.Service.Product,
				ExtraInfo: port.Service.ExtraInfo,
			},
		})
	}
	return items
}

func mapOS(osInfo nmap.OS) *models.OSInfo {
	if len(osInfo.Matches) == 0 {
		return nil
	}

	match := osInfo.Matches[0]
	return &models.OSInfo{
		Name:     match.Name,
		Accuracy: match.Accuracy,
	}
}

func extractCVEs(host nmap.Host) []models.CVE {
	var scripts []nmap.Script
	scripts = append(scripts, host.HostScripts...)
	for _, port := range host.Ports {
		scripts = append(scripts, port.Scripts...)
	}

	return extractCVEsFromScripts(scripts)
}

func extractCVEsFromScripts(scripts []nmap.Script) []models.CVE {
	if len(scripts) == 0 {
		return nil
	}

	cveRegex := regexp.MustCompile(`CVE-\d{4}-\d+`)
	floatRegex := regexp.MustCompile(`\b\d+\.\d+\b`)
	results := make(map[string]models.CVE)

	for _, script := range scripts {
		if script.ID != "vulners" {
			continue
		}

		for _, id := range cveRegex.FindAllString(script.Output, -1) {
			results[id] = models.CVE{
				ID:     id,
				URL:    fmt.Sprintf("https://vulners.com/cve/%s", id),
				Source: "vulners",
			}
		}

		for _, line := range strings.Split(script.Output, "\n") {
			if !cveRegex.MatchString(line) {
				continue
			}
			ids := cveRegex.FindAllString(line, -1)
			match := floatRegex.FindString(line)
			if match == "" {
				continue
			}
			score, err := strconv.ParseFloat(match, 64)
			if err != nil {
				continue
			}
			for _, id := range ids {
				entry := results[id]
				entry.Score = score
				if entry.URL == "" {
					entry.URL = fmt.Sprintf("https://vulners.com/cve/%s", id)
				}
				entry.Source = "vulners"
				results[id] = entry
			}
		}

		for _, elem := range script.Elements {
			collectCVEsFromElement(elem, results)
		}
		for _, table := range script.Tables {
			collectCVEsFromTable(table, results)
		}
	}

	if len(results) == 0 {
		return nil
	}

	items := make([]models.CVE, 0, len(results))
	for _, cve := range results {
		items = append(items, cve)
	}

	return items
}

func collectCVEsFromElement(elem nmap.Element, results map[string]models.CVE) {
	if elem.Key == "id" {
		id := strings.TrimSpace(elem.Value)
		if strings.HasPrefix(id, "CVE-") {
			results[id] = models.CVE{
				ID:     id,
				URL:    fmt.Sprintf("https://vulners.com/cve/%s", id),
				Source: "vulners",
			}
		}
		return
	}

	for _, id := range regexp.MustCompile(`CVE-\d{4}-\d+`).FindAllString(elem.Value, -1) {
		results[id] = models.CVE{
			ID:     id,
			URL:    fmt.Sprintf("https://vulners.com/cve/%s", id),
			Source: "vulners",
		}
	}
}

func collectCVEsFromTable(table nmap.Table, results map[string]models.CVE) {
	for _, elem := range table.Elements {
		collectCVEsFromElement(elem, results)
	}
	for _, nested := range table.Tables {
		collectCVEsFromTable(nested, results)
	}
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}
