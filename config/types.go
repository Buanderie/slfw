package config

// PortRange represents a range of ports
type PortRange struct {
	Start uint16 `yaml:"start"`
	End   uint16 `yaml:"end"`
}

// FirewallRule represents the firewall_rule_t struct for YAML parsing
type FirewallRule struct {
	RuleName    string     `yaml:"rule_name"`
	Action      string     `yaml:"action"`
	Protocol    string     `yaml:"protocol"`
	IP          string     `yaml:"ip"`
	PortRange   *PortRange `yaml:"port_range,omitempty"` // Used for parsing
	Port        string     `yaml:"port,omitempty"`       // Used for parsing
	Description string     `yaml:"description"`
}

// FirewallConfig represents the top-level firewall configuration
type FirewallConfig struct {
	Inbound        []FirewallRule `yaml:"inbound"`
	Outbound       []FirewallRule `yaml:"outbound"`
	InboundPolicy  string        `yaml:"inbound_policy"`
	OutboundPolicy string        `yaml:"outbound_policy"`
}

// RuleValue represents the firewall_rule_t struct for eBPF map
type RuleValue struct {
	RuleName     [128]byte // char rule_name[128]
	Action       uint8     // __u8
	_            [1]byte   // padding for alignment
	Protocol     uint16    // __u16
	IP           uint32    // __u32
	Netmask      uint32    // __u32
	HasPortRange uint8     // __u8
	_            [1]byte   // padding for alignment
	PortInfo     [4]byte   // union { __u16 port; port_range_t port_range; }
	Used         uint8     // __u8
	Enabled      uint8     // __u8
}

// RuleKey represents the eBPF map key
type RuleKey uint32