package models

type Customer struct {
	ID           string           `yaml:"id" json:"id"`
	Name         string           `yaml:"name" json:"name"`
	Confidence   float64          `yaml:"confidence" json:"confidence"`
	Description  string           `yaml:"description" json:"description"`
	Fingerprints []Fingerprint    `yaml:"fingerprints" json:"fingerprints"`
	Networks     CustomerNetworks `yaml:"networks" json:"networks"`
	Metadata     CustomerMetadata `yaml:"metadata" json:"metadata"`
}

type CustomerNetworks struct {
	ExitIPs          interface{}            `yaml:"exit_ips" json:"exit_ips"`
	PublicIP         string                 `yaml:"public_ip" json:"public_ip"`
	PublicIPs        []string               `yaml:"public_ips" json:"public_ips"`
	LabeledPublicIPs map[string]interface{} `yaml:"labeled_public_ips" json:"labeled_public_ips"`
	PrivateRanges    []string               `yaml:"private_ranges" json:"private_ranges"`
	GatewayPattern   string                 `yaml:"gateway_pattern" json:"gateway_pattern"`
}

type CustomerMetadata struct {
	NetworkSize string `yaml:"network_size" json:"network_size"`
}

type Fingerprint struct {
	Type              string         `yaml:"type" json:"type"`
	Description       string         `yaml:"description" json:"description"`
	HopCount          string         `yaml:"hop_count" json:"hop_count"`
	LatencyProfile    LatencyProfile `yaml:"latency_profile" json:"latency_profile"`
	PrivateHopPattern []HopPattern   `yaml:"private_hop_pattern" json:"private_hop_pattern"`
	PublicExitPattern []HopPattern   `yaml:"public_exit_pattern" json:"public_exit_pattern"`
}

type HopPattern struct {
	Position  interface{} `yaml:"position" json:"position"`
	IPPattern string      `yaml:"ip_pattern" json:"ip_pattern"`
	IsPrivate bool        `yaml:"is_private" json:"is_private"`
}

type LatencyProfile struct {
	FirstHop  string `yaml:"first_hop" json:"first_hop"`
	ExitHop   string `yaml:"exit_hop" json:"exit_hop"`
	TotalTime string `yaml:"total_time" json:"total_time"`
}

type NetworkKey struct {
	Signature   string `json:"signature" yaml:"signature"`
	Hops        []Hop  `json:"hops" yaml:"hops"`
	PrivateHops []Hop  `json:"private_hops" yaml:"private_hops"`
	PublicHops  []Hop  `json:"public_hops" yaml:"public_hops"`
	TotalHops   int    `json:"total_hops" yaml:"total_hops"`
	ExitIP      string `json:"exit_ip" yaml:"exit_ip"`
	PublicIP    string `json:"public_ip" yaml:"public_ip"`
	Target      string `json:"target" yaml:"target"`
	Raw         string `json:"raw" yaml:"raw"`
}

type Hop struct {
	Hop       int     `json:"hop" yaml:"hop"`
	IP        string  `json:"ip" yaml:"ip"`
	LatencyMS float64 `json:"latency_ms" yaml:"latency_ms"`
	IsPrivate bool    `json:"is_private" yaml:"is_private"`
}

type TracerouteHistory struct {
	Name        string            `json:"name" yaml:"name"`
	Traceroutes []TracerouteEntry `json:"traceroutes" yaml:"traceroutes"`
}

type TracerouteEntry struct {
	Timestamp        string `json:"timestamp" yaml:"timestamp"`
	PublicIP         string `json:"public_ip" yaml:"public_ip"`
	ExitIP           string `json:"exit_ip" yaml:"exit_ip"`
	HopCount         int    `json:"hop_count" yaml:"hop_count"`
	NetworkSignature string `json:"network_signature" yaml:"network_signature"`
	Label            string `json:"label" yaml:"label"`
	RawTraceroute    string `json:"raw_traceroute" yaml:"raw_traceroute"`
}
