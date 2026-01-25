package scanner

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/techmore/nmapui/internal/models"
)

type ProgressPublisher interface {
	Publish(event string, payload any)
}

type ScanEngine struct {
	maxConcurrent int
	hub           ProgressPublisher
	scanner       *NmapScanner

	scanStartTime time.Time
	totalHosts    int64
	hostsScanned  int64
}

func NewScanEngine(scanner *NmapScanner, hub ProgressPublisher, maxConcurrent int) *ScanEngine {
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}

	return &ScanEngine{
		maxConcurrent: maxConcurrent,
		hub:           hub,
		scanner:       scanner,
	}
}

func (e *ScanEngine) QuickScan(ctx context.Context, target string) ([]models.Host, error) {
	config := e.GetAdaptiveScanConfig([]string{target})

	e.emit("quick_scan_start", map[string]any{
		"target": target,
	})

	result, err := e.scanner.QuickScan(ctx, target, config.TimingProfile)
	if err != nil {
		e.emit("scan_error", map[string]any{
			"target": target,
			"error":  err.Error(),
		})
		return nil, err
	}

	e.emit("quick_scan_complete", map[string]any{
		"target":     target,
		"live_hosts": len(result),
		"hosts":      result,
	})

	return result, nil
}

func (e *ScanEngine) ARPScan(ctx context.Context, target string) ([]models.Host, error) {
	config := e.GetAdaptiveScanConfig([]string{target})

	e.emit("arp_scan_start", map[string]any{
		"target": target,
	})

	result, err := e.scanner.ARPScan(ctx, target, config.TimingProfile)
	if err != nil {
		e.emit("scan_error", map[string]any{
			"target": target,
			"error":  err.Error(),
		})
		return nil, err
	}

	e.emit("arp_scan_complete", map[string]any{
		"target":     target,
		"live_hosts": len(result),
		"hosts":      result,
	})

	return result, nil
}

func (e *ScanEngine) DeepScan(ctx context.Context, targets []string) (models.ScanResult, error) {
	result := models.ScanResult{ScanID: uuid.NewString()}
	if len(targets) == 0 {
		return result, nil
	}

	config := e.GetAdaptiveScanConfig(targets)
	effectiveMax := minInt(len(targets), minInt(config.MaxConcurrent, e.maxConcurrent))
	if effectiveMax <= 0 {
		effectiveMax = 1
	}

	result.TotalHosts = len(targets)
	result.StartedAt = time.Now()
	e.scanStartTime = result.StartedAt
	atomic.StoreInt64(&e.totalHosts, int64(result.TotalHosts))
	atomic.StoreInt64(&e.hostsScanned, 0)

	e.emit("deep_scan_start", map[string]any{
		"scan_id": result.ScanID,
		"total_hosts": result.TotalHosts,
		"config": map[string]any{
			"scan_type":      config.ScanType,
			"max_concurrent": effectiveMax,
			"timing":         config.TimingProfile,
			"top_ports":      config.TopPorts,
			"timeout":        config.Timeout.Seconds(),
		},
	})

	pool := NewPool(effectiveMax)
	var resultsMu sync.Mutex
	results := make([]models.Host, 0, len(targets))
	problems := make([]string, 0)

	tasks := make([]Task, 0, len(targets))
	for _, target := range targets {
		target := target
		tasks = append(tasks, func(taskCtx context.Context) error {
			scanStart := time.Now()
			scanCtx := taskCtx
			var cancel context.CancelFunc
			if config.Timeout > 0 {
				scanCtx, cancel = context.WithTimeout(taskCtx, config.Timeout)
			} else {
				cancel = func() {}
			}
			defer cancel()

			host, err := e.scanner.DeepScan(scanCtx, target, config)
			host.ScanTime = time.Since(scanStart)
			if err != nil {
				host.Status = "error"
				host.Error = err.Error()
			}

			resultsMu.Lock()
			results = append(results, host)
			if err != nil {
				problems = append(problems, err.Error())
			}
			resultsMu.Unlock()

			e.emit("deep_scan_host_complete", map[string]any{
				"scan_id": result.ScanID,
				"ip":      target,
				"result":  host,
			})

			if len(host.CVEs) > 0 {
				e.emit("cve_array", map[string]any{
					"scan_id":  result.ScanID,
					"target":   target,
					"cve_array": host.CVEs,
				})
			}

			e.updateProgress()
			return err
		})
	}

	errList := pool.Run(ctx, tasks)
	if err := CombineErrors(errList); err != nil {
		problems = append(problems, err.Error())
	}

	result.Hosts = results
	result.Errors = problems
	result.HostsScanned = int(atomic.LoadInt64(&e.hostsScanned))
	result.CompletedAt = time.Now()

	e.emit("deep_scan_complete", map[string]any{
		"scan_id": result.ScanID,
		"total_results": len(results),
		"successful_scans": countSuccessful(results),
		"total_time": time.Since(result.StartedAt).Seconds(),
		"avg_scan_rate": e.scanRate(),
	})

	if len(errList) > 0 {
		return result, CombineErrors(errList)
	}

	return result, nil
}

func (e *ScanEngine) GetAdaptiveScanConfig(targets []string) models.ScanConfig {
	hostCount := estimateTargets(targets)

	switch {
	case hostCount <= 50:
		return models.ScanConfig{
			TimingProfile: "aggressive",
			TopPorts:      1000,
			Timeout:       300 * time.Second,
			MaxConcurrent: 5,
			ScanType:      "fast",
		}
	case hostCount <= 200:
		return models.ScanConfig{
			TimingProfile: "normal",
			TopPorts:      500,
			Timeout:       600 * time.Second,
			MaxConcurrent: 8,
			ScanType:      "balanced",
		}
	case hostCount <= 1000:
		return models.ScanConfig{
			TimingProfile: "polite",
			TopPorts:      200,
			Timeout:       1200 * time.Second,
			MaxConcurrent: 10,
			ScanType:      "thorough",
		}
	default:
		return models.ScanConfig{
			TimingProfile: "polite",
			TopPorts:      100,
			Timeout:       1800 * time.Second,
			MaxConcurrent: 10,
			ScanType:      "conservative",
		}
	}
}

func (e *ScanEngine) updateProgress() {
	current := atomic.AddInt64(&e.hostsScanned, 1)
	total := atomic.LoadInt64(&e.totalHosts)

	elapsed := time.Since(e.scanStartTime)
	if elapsed <= 0 {
		elapsed = time.Second
	}

	rate := float64(current) / elapsed.Seconds()
	etaSeconds := 0.0
	if rate > 0 && total > current {
		remaining := float64(total - current)
		etaSeconds = remaining / rate
	}

	percentage := 0.0
	if total > 0 {
		percentage = float64(current) / float64(total) * 100
	}

	e.emit("scan_progress", map[string]any{
		"scanned":           current,
		"total":             total,
		"percentage":        math.Round(percentage*100) / 100,
		"hosts_per_second":  math.Round(rate*100) / 100,
		"eta_seconds":       int(etaSeconds),
		"eta_formatted":     formatDuration(time.Duration(etaSeconds) * time.Second),
		"elapsed_seconds":   int(elapsed.Seconds()),
		"scan_rate_per_sec": math.Round(rate*100) / 100,
	})
}

func (e *ScanEngine) scanRate() float64 {
	current := atomic.LoadInt64(&e.hostsScanned)
	if current == 0 {
		return 0
	}
	elapsed := time.Since(e.scanStartTime)
	if elapsed <= 0 {
		return 0
	}
	return float64(current) / elapsed.Seconds()
}

func (e *ScanEngine) emit(event string, payload any) {
	if e.hub == nil {
		return
	}

	go func() {
		defer func() {
			_ = recover()
		}()
		e.hub.Publish(event, payload)
	}()
}

func estimateTargets(targets []string) int {
	count := 0
	for _, target := range targets {
		count += estimateHosts(target)
	}
	if count == 0 {
		return 1
	}
	return count
}

func estimateHosts(target string) int {
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err != nil {
			return 254
		}
		if prefix.Addr().Is4() {
			bits := 32 - prefix.Bits()
			if bits < 0 || bits > 32 {
				return 254
			}
			return 1 << bits
		}
		return 1
	}

	if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		if len(parts) != 2 {
			return 254
		}
		start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
		if err != nil {
			return 254
		}
		end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil {
			return 254
		}
		if !start.Is4() || !end.Is4() {
			return 1
		}
		startNum := ipv4ToUint32(start)
		endNum := ipv4ToUint32(end)
		if endNum < startNum {
			return int(startNum-endNum) + 1
		}
		return int(endNum-startNum) + 1
	}

	if _, err := netip.ParseAddr(target); err == nil {
		return 1
	}

	return 254
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func formatDuration(duration time.Duration) string {
	seconds := int(duration.Seconds())
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		minutes := seconds / 60
		remaining := seconds % 60
		return fmt.Sprintf("%dm %ds", minutes, remaining)
	}
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func countSuccessful(hosts []models.Host) int {
	count := 0
	for _, host := range hosts {
		if host.Status != "error" {
			count++
		}
	}
	return count
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
