package fingerprint

import (
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/techmore/nmapui/internal/models"
)

const (
	exitIPWeight      = 0.30
	hopPatternWeight  = 0.40
	latencyWeight     = 0.20
	networkSizeWeight = 0.10
)

func (cf *CustomerFingerprinter) AggregateScore(nk *models.NetworkKey, customer *models.Customer) float64 {
	if nk == nil || customer == nil {
		return 0.0
	}

	exitScore := cf.calculateExitIPScore(nk, customer)
	hopScore, latencyScore := cf.bestFingerprintScores(nk, customer)
	networkScore := cf.calculateNetworkSizeScore(nk, customer)

	return (exitScore * exitIPWeight) + (hopScore * hopPatternWeight) + (latencyScore * latencyWeight) + (networkScore * networkSizeWeight)
}

func (cf *CustomerFingerprinter) bestFingerprintScores(nk *models.NetworkKey, customer *models.Customer) (float64, float64) {
	bestHop := 0.0
	bestLatency := 0.0
	bestCombined := -1.0

	for i := range customer.Fingerprints {
		fp := &customer.Fingerprints[i]
		hopScore := cf.calculateHopPatternScore(nk, fp)
		latencyScore := cf.calculateLatencyScore(nk, fp)
		combined := (hopScore * hopPatternWeight) + (latencyScore * latencyWeight)
		if combined > bestCombined {
			bestCombined = combined
			bestHop = hopScore
			bestLatency = latencyScore
		}
	}

	return bestHop, bestLatency
}

func (cf *CustomerFingerprinter) calculateExitIPScore(nk *models.NetworkKey, customer *models.Customer) float64 {
	exitIP := nk.ExitIP
	publicIP := nk.PublicIP
	if exitIP == "" {
		return 0.0
	}

	exitIPs := customer.Networks.ExitIPs
	customerPublicIP := customer.Networks.PublicIP

	if exitIPs != "dynamic" {
		for _, pattern := range normalizeExitIPs(exitIPs) {
			if cf.MatchIPPattern(exitIP, pattern) {
				return 1.0
			}
		}
	}

	if customerPublicIP != "" && customerPublicIP != "dynamic" && publicIP != "" {
		if ipInCIDR(publicIP, customerPublicIP) {
			return 0.9
		}
	}

	if publicIP != "" && customerPublicIP != "" && customerPublicIP != "dynamic" {
		if ipInCIDR(exitIP, customerPublicIP) {
			return 0.7
		}
	}

	if len(nk.Hops) > 5 {
		return 0.6
	}

	return 0.0
}

func (cf *CustomerFingerprinter) calculateHopPatternScore(nk *models.NetworkKey, fingerprint *models.Fingerprint) float64 {
	if nk == nil || fingerprint == nil {
		return 0.0
	}
	hops := nk.Hops
	if fingerprint.HopCount != "" && !cf.MatchHopCountRange(len(hops), fingerprint.HopCount) {
		return 0.0
	}

	score := 0.5
	maxScore := 0.5

	for _, pattern := range fingerprint.PrivateHopPattern {
		maxScore += 0.25
		if matchPatternOnHop(hops, pattern, true, cf) {
			score += 0.25
		}
	}

	for _, pattern := range fingerprint.PublicExitPattern {
		maxScore += 0.25
		if matchPatternOnHop(hops, pattern, false, cf) {
			score += 0.25
		}
	}

	if maxScore <= 0 {
		return 0.0
	}
	return math.Min(score/maxScore, 1.0)
}

func (cf *CustomerFingerprinter) calculateLatencyScore(nk *models.NetworkKey, fingerprint *models.Fingerprint) float64 {
	if nk == nil || fingerprint == nil {
		return 0.0
	}
	hops := nk.Hops
	if len(hops) == 0 {
		return 0.0
	}

	profile := fingerprint.LatencyProfile
	score := 0.0
	maxScore := 0.0

	if profile.FirstHop != "" {
		maxScore += 0.33
		if cf.MatchLatencyRange(hops[0].LatencyMS, profile.FirstHop) {
			score += 0.33
		}
	}
	if profile.ExitHop != "" {
		maxScore += 0.33
		if cf.MatchLatencyRange(hops[len(hops)-1].LatencyMS, profile.ExitHop) {
			score += 0.33
		}
	}
	if profile.TotalTime != "" {
		maxScore += 0.34
		totalLatency := 0.0
		for _, hop := range hops {
			if hop.LatencyMS != 0 {
				totalLatency += hop.LatencyMS
			}
		}
		if cf.MatchLatencyRange(totalLatency, profile.TotalTime) {
			score += 0.34
		}
	}

	if maxScore <= 0 {
		return 0.0
	}
	return score / maxScore
}

func (cf *CustomerFingerprinter) calculateNetworkSizeScore(nk *models.NetworkKey, customer *models.Customer) float64 {
	if nk == nil || customer == nil {
		return 0.0
	}
	privateCount := len(nk.PrivateHops)
	networkSize := customer.Metadata.NetworkSize

	switch networkSize {
	case "small":
		if privateCount <= 2 {
			return 1.0
		}
	case "medium":
		if privateCount > 2 && privateCount <= 4 {
			return 1.0
		}
	case "large":
		if privateCount > 4 {
			return 1.0
		}
	}

	return 0.5
}

func matchPatternOnHop(hops []models.Hop, pattern models.HopPattern, requirePrivate bool, cf *CustomerFingerprinter) bool {
	if cf == nil || len(hops) == 0 {
		return false
	}
	pos := pattern.Position
	if isLastPosition(pos) {
		hop := hops[len(hops)-1]
		if hop.IsPrivate != requirePrivate {
			return false
		}
		return cf.MatchIPPattern(hop.IP, pattern.IPPattern)
	}
	idx := positionIndex(pos)
	if idx <= 0 || idx > len(hops) {
		return false
	}
	hop := hops[idx-1]
	if hop.IsPrivate != requirePrivate {
		return false
	}
	return cf.MatchIPPattern(hop.IP, pattern.IPPattern)
}

func isLastPosition(pos interface{}) bool {
	if str, ok := pos.(string); ok {
		return strings.ToLower(str) == "last"
	}
	return false
}

func positionIndex(pos interface{}) int {
	switch v := pos.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		val, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return val
	default:
		return 0
	}
}

func normalizeExitIPs(exitIPs interface{}) []string {
	if exitIPs == nil {
		return nil
	}
	switch v := exitIPs.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []interface{}:
		values := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				values = append(values, str)
			}
		}
		return values
	default:
		return nil
	}
}

func ipInCIDR(ip string, cidr string) bool {
	if ip == "" || cidr == "" {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network == nil {
		return false
	}
	return network.Contains(parsedIP)
}
