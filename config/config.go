package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

// LoadConfig reads and parses the YAML configuration file
func LoadConfig(filePath string) (*FirewallConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var config FirewallConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}
	// Set default policies if not specified
	if config.InboundPolicy == "" {
		config.InboundPolicy = "DROP"
	}
	if config.OutboundPolicy == "" {
		config.OutboundPolicy = "DROP"
	}
	// Validate policies
	if strings.ToUpper(config.InboundPolicy) != "ACCEPT" && strings.ToUpper(config.InboundPolicy) != "DROP" {
		return nil, fmt.Errorf("invalid inbound_policy: %s, must be 'ACCEPT' or 'DROP'", config.InboundPolicy)
	}
	if strings.ToUpper(config.OutboundPolicy) != "ACCEPT" && strings.ToUpper(config.OutboundPolicy) != "DROP" {
		return nil, fmt.Errorf("invalid outbound_policy: %s, must be 'ACCEPT' or 'DROP'", config.OutboundPolicy)
	}
	return &config, nil
}