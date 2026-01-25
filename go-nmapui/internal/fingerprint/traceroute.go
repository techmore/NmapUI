package fingerprint

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/techmore/nmapui/internal/models"
)

var (
	tracerouteLinePattern = regexp.MustCompile(`(?m)^\s*(\d+)\s+(\S+)\s+(.+)$`)
	latencyPattern        = regexp.MustCompile(`([\d.]+)\s*ms`)
)

func (cf *CustomerFingerprinter) RunTraceroute(ctx context.Context, target string) (*models.NetworkKey, error) {
	if target == "" {
		target = "1.1.1.1"
	}

	cmd := exec.CommandContext(ctx, "traceroute", "-n", target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	publicIP, _ := fetchPublicIP(ctx)
	hops := parseTracerouteOutput(output, cf)
	return generateNetworkKey(hops, target, publicIP, string(output), cf), nil
}

func parseTracerouteOutput(output []byte, cf *CustomerFingerprinter) []models.Hop {
	if cf == nil {
		return nil
	}
	text := string(bytes.TrimSpace(output))
	if text == "" {
		return nil
	}

	var hops []models.Hop
	matches := tracerouteLinePattern.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		hopNum, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		ipOrStar := match[2]
		if ipOrStar == "*" || strings.Contains(strings.ToLower(ipOrStar), "traceroute") {
			continue
		}

		latencyMatches := latencyPattern.FindAllStringSubmatch(match[3], -1)
		avgLatency := 0.0
		if len(latencyMatches) > 0 {
			var sum float64
			for _, lm := range latencyMatches {
				if len(lm) < 2 {
					continue
				}
				val, err := strconv.ParseFloat(lm[1], 64)
				if err != nil {
					continue
				}
				sum += val
			}
			avgLatency = math.RoundToEven((sum/float64(len(latencyMatches)))*100) / 100
		}

		hops = append(hops, models.Hop{
			Hop:       hopNum,
			IP:        ipOrStar,
			LatencyMS: avgLatency,
			IsPrivate: cf.IsPrivateIP(ipOrStar),
		})
	}

	return hops
}

func generateNetworkKey(hops []models.Hop, target string, publicIP string, raw string, cf *CustomerFingerprinter) *models.NetworkKey {
	nk := &models.NetworkKey{
		Hops:      hops,
		Target:    target,
		PublicIP:  publicIP,
		Raw:       raw,
		TotalHops: len(hops),
	}
	if len(hops) > 0 {
		nk.ExitIP = hops[len(hops)-1].IP
	}
	for _, hop := range hops {
		if hop.IsPrivate {
			nk.PrivateHops = append(nk.PrivateHops, hop)
		} else {
			nk.PublicHops = append(nk.PublicHops, hop)
		}
	}
	if cf != nil {
		nk.Signature = cf.CreateNetworkSignature(nk)
	}
	return nk
}

func fetchPublicIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("failed to fetch public IP")
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}
