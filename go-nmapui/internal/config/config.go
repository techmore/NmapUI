package config

import (
	"os"
	"strconv"
)

// Config holds all application configuration
type Config struct {
	// Server
	Port int

	// Database
	DatabasePath string

	// Scanner
	NmapPath      string
	MaxConcurrent int

	// Fingerprinting
	CustomersYAML string

	// Reports
	XSLPath    string
	TempDir    string
	AppVersion string

	// WebSocket
	WSBufferSize int
}

// Load reads configuration from environment variables with defaults
func Load() *Config {
	return &Config{
		Port:          getEnvInt("PORT", 9000),
		DatabasePath:  getEnv("DB_PATH", "data/nmapui.db"),
		NmapPath:      getEnv("NMAP_PATH", "nmap"),
		MaxConcurrent: getEnvInt("MAX_CONCURRENT", 10),
		CustomersYAML: getEnv("CUSTOMERS_YAML", "config/customers.yaml"),
		XSLPath:       getEnv("XSL_PATH", "web/static/nmap-pdf-olive-legacy.xsl"),
		TempDir:       getEnv("TEMP_DIR", "data/temp"),
		AppVersion:    getEnv("APP_VERSION", "1.0.0-go"),
		WSBufferSize:  getEnvInt("WS_BUFFER_SIZE", 256),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
