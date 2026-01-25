package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/techmore/nmapui/internal/models"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version         string                 `yaml:"version"`
	Description     string                 `yaml:"description"`
	Settings        map[string]interface{} `yaml:"settings"`
	Customers       []models.Customer      `yaml:"customers"`
	UnknownCustomer map[string]interface{} `yaml:"unknown_customer"`
	Indexing        map[string]interface{} `yaml:"indexing"`
}

type CustomerFingerprinter struct {
	ConfigPath          string
	Config              *Config
	Customers           []models.Customer
	UnknownCustomer     map[string]interface{}
	Settings            map[string]interface{}
	TraceroutesPath     string
	CustomerTraceroutes map[string]*models.TracerouteHistory
	LastMatchMethod     string
}

func NewCustomerFingerprinter(configPath string) *CustomerFingerprinter {
	path := configPath
	if path == "" {
		path = filepath.Join("config", "customers.yaml")
	}

	cf := &CustomerFingerprinter{
		ConfigPath:          path,
		TraceroutesPath:     filepath.Join("data", "customer_traceroutes.json"),
		CustomerTraceroutes: map[string]*models.TracerouteHistory{},
		Settings:            map[string]interface{}{},
		UnknownCustomer:     map[string]interface{}{},
	}

	cf.loadConfig()
	cf.loadTracerouteHistory()
	return cf
}

func (cf *CustomerFingerprinter) IdentifyCustomer(ctx context.Context, nk *models.NetworkKey) (string, float64, error) {
	if nk == nil {
		return "Unknown", 0, errors.New("network key is nil")
	}

	_ = ctx
	bestID := ""
	bestScore := 0.0
	bestConfidence := 0.0

	for i := range cf.Customers {
		customer := &cf.Customers[i]
		score := cf.AggregateScore(nk, customer)
		if score > bestScore {
			bestScore = score
			bestID = customer.ID
			bestConfidence = customer.Confidence
		}
	}

	if bestID == "" {
		return "Unknown", 0.0, nil
	}

	cf.LastMatchMethod = "multi_factor"
	if bestScore >= bestConfidence {
		return bestID, bestScore, nil
	}

	return "Unknown", 0.0, nil
}

func (cf *CustomerFingerprinter) loadConfig() {
	data, err := os.ReadFile(cf.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("customer config not found at %s", cf.ConfigPath)
		} else {
			log.Printf("error reading customer config: %v", err)
		}
		cf.Config = &Config{}
		cf.Customers = nil
		cf.Settings = map[string]interface{}{}
		cf.UnknownCustomer = map[string]interface{}{}
		return
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("error parsing customer config: %v", err)
		cf.Config = &Config{}
		cf.Customers = nil
		cf.Settings = map[string]interface{}{}
		cf.UnknownCustomer = map[string]interface{}{}
		return
	}

	cf.Config = &cfg
	cf.Settings = cfg.Settings
	cf.Customers = cfg.Customers
	if cfg.UnknownCustomer != nil {
		cf.UnknownCustomer = cfg.UnknownCustomer
	}
	log.Printf("loaded %d customer configurations", len(cf.Customers))
}

func (cf *CustomerFingerprinter) loadTracerouteHistory() {
	if _, err := os.Stat(cf.TraceroutesPath); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(cf.TraceroutesPath), 0o755); err != nil {
				log.Printf("failed to create traceroute history directory: %v", err)
				return
			}
			if err := cf.writeTracerouteHistory(map[string]*models.TracerouteHistory{}); err != nil {
				log.Printf("failed to initialize traceroute history: %v", err)
			}
			return
		}
		log.Printf("error checking traceroute history: %v", err)
		return
	}

	data, err := os.ReadFile(cf.TraceroutesPath)
	if err != nil {
		log.Printf("error reading traceroute history: %v", err)
		return
	}

	var history map[string]*models.TracerouteHistory
	if err := json.Unmarshal(data, &history); err != nil {
		log.Printf("error parsing traceroute history: %v", err)
		return
	}
	if history == nil {
		history = map[string]*models.TracerouteHistory{}
	}
	cf.CustomerTraceroutes = history
}

func (cf *CustomerFingerprinter) SaveTracerouteToHistory(customerID string, nk *models.NetworkKey, label string) {
	if nk == nil {
		return
	}

	entry := models.TracerouteEntry{
		Timestamp:        time.Now().Format(time.RFC3339),
		PublicIP:         nk.PublicIP,
		ExitIP:           nk.ExitIP,
		HopCount:         len(nk.Hops),
		NetworkSignature: cf.CreateNetworkSignature(nk),
		Label:            label,
		RawTraceroute:    nk.Raw,
	}
	if entry.Label == "" {
		if nk.PublicIP != "" {
			entry.Label = nk.PublicIP
		} else {
			entry.Label = "unknown"
		}
	}

	if customerID != "" {
		history := cf.CustomerTraceroutes[customerID]
		if history == nil {
			history = &models.TracerouteHistory{Name: customerID}
			cf.CustomerTraceroutes[customerID] = history
		}
		history.Traceroutes = append(history.Traceroutes, entry)
	}

	if err := os.MkdirAll(filepath.Dir(cf.TraceroutesPath), 0o755); err != nil {
		log.Printf("failed to create traceroute history directory: %v", err)
		return
	}
	if err := cf.writeTracerouteHistory(cf.CustomerTraceroutes); err != nil {
		log.Printf("error saving traceroute history: %v", err)
	}
}

func (cf *CustomerFingerprinter) writeTracerouteHistory(history map[string]*models.TracerouteHistory) error {
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cf.TraceroutesPath, data, 0o644)
}

func (cf *CustomerFingerprinter) CreateNetworkSignature(nk *models.NetworkKey) string {
	if nk == nil {
		return ""
	}
	parts := make([]string, 0, len(nk.Hops))
	for _, hop := range nk.Hops {
		masked := maskIP(hop.IP)
		prefix := "public"
		if hop.IsPrivate {
			prefix = "private"
		}
		parts = append(parts, prefix+":"+masked)
	}
	return strings.Join(parts, " -> ")
}

func maskIP(ip string) string {
	segments := strings.Split(ip, ".")
	if len(segments) < 2 {
		return ip
	}
	return segments[0] + "." + segments[1] + ".x.x"
}

func (cf *CustomerFingerprinter) MatchIPPattern(ip string, pattern string) bool {
	if pattern == "dynamic" {
		return true
	}
	if ip == "" || pattern == "" {
		return false
	}

	if strings.Contains(pattern, "*") {
		regexPattern := strings.ReplaceAll(pattern, "*", `\\d+`)
		re, err := regexp.Compile("^" + regexPattern)
		if err != nil {
			return false
		}
		return re.MatchString(ip)
	}

	return ip == pattern
}

func (cf *CustomerFingerprinter) MatchLatencyRange(latencyMS float64, rangeStr string) bool {
	if latencyMS == 0 || rangeStr == "" {
		return false
	}

	value := strings.ReplaceAll(rangeStr, "ms", "")
	value = strings.ReplaceAll(value, "<", "")
	value = strings.ReplaceAll(value, ">", "")
	value = strings.TrimSpace(value)

	if strings.Contains(value, "<") {
		maxVal, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return false
		}
		return latencyMS < maxVal
	}
	if strings.Contains(value, ">") {
		minVal, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return false
		}
		return latencyMS > minVal
	}
	if strings.Contains(value, "-") {
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			return false
		}
		minVal, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		if err != nil {
			return false
		}
		maxVal, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			return false
		}
		return latencyMS >= minVal && latencyMS <= maxVal
	}

	matchVal, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return false
	}
	if latencyMS > matchVal {
		return latencyMS-matchVal < 1.0
	}
	return matchVal-latencyMS < 1.0
}

func (cf *CustomerFingerprinter) MatchHopCountRange(count int, rangeStr string) bool {
	if rangeStr == "" {
		return false
	}
	if strings.Contains(rangeStr, "-") {
		parts := strings.Split(rangeStr, "-")
		if len(parts) != 2 {
			return false
		}
		minVal, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return false
		}
		maxVal, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false
		}
		return count >= minVal && count <= maxVal
	}
	val, err := strconv.Atoi(strings.TrimSpace(rangeStr))
	if err != nil {
		return false
	}
	return count == val
}

func (cf *CustomerFingerprinter) IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
