package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" InboundBPF ./bpf/inbound.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" OutboundBPF ./bpf/outbound.c

// PortRange represents a range of ports
type PortRange struct {
	Start int32 `yaml:"start"`
	End   int32 `yaml:"end"`
}

// FirewallRule represents the firewall_rule_t struct for YAML parsing
type FirewallRule struct {
	RuleName    string     `yaml:"rule_name"`
	Action      string     `yaml:"action"`
	Protocol    string     `yaml:"protocol"`
	IP          string     `yaml:"ip"`
	HasPortRange int32      `yaml:"-"` // Set programmatically
	PortInfo     [8]byte    `yaml:"-"` // Union: port (int32) or port_range (start, end as int32)
	Description  string     `yaml:"description"`
	PortRange    *PortRange `yaml:"port_range"` // Used for parsing
	Port         string     `yaml:"port"`       // Used for parsing
}

// RuleValue represents the firewall_rule_t struct for eBPF map
type RuleValue struct {
	RuleName    [128]byte
	Action      [16]byte
	Protocol    [16]byte
	IP          [46]byte
	HasPortRange int32
	PortInfo     [8]byte
	Description  [256]byte
}

// FirewallConfig represents the top-level firewall configuration
type FirewallConfig struct {
	Inbound        []FirewallRule `yaml:"inbound"`
	Outbound       []FirewallRule `yaml:"outbound"`
	InboundPolicy  string        `yaml:"inbound_policy"`
	OutboundPolicy string        `yaml:"outbound_policy"`
}

// eBPF map structures
type RuleKey uint32 // Array index

func parseIPWithCIDR(ipStr string) (string, error) {
	if ipStr == "any" {
		return ipStr, nil
	}
	if ip := net.ParseIP(ipStr); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("only IPv4 is supported")
		}
		return ipStr, nil // Single IP
	}
	_, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		return "", fmt.Errorf("invalid IP/CIDR %s: %v", ipStr, err)
	}
	return ipStr, nil
}

func parsePort(portStr string) (int32, error) {
	if portStr == "" || portStr == "any" {
		return 0, nil
	}
	var port int32
	_, err := fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port %s: %v", portStr, err)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port %s out of range (0-65535)", portStr)
	}
	return port, nil
}

func loadConfig(filePath string) (*FirewallConfig, error) {
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

// setDefaultPolicy updates the default policy map with the specified policy
func setDefaultPolicy(policyMap *ebpf.Map, policy string, direction string) error {
	var defaultKey uint32 = 0
	defaultAction := uint8(0) // DROP
	if strings.ToUpper(policy) == "ACCEPT" {
		defaultAction = 1
	}
	if err := policyMap.Update(unsafe.Pointer(&defaultKey), unsafe.Pointer(&defaultAction), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("error setting %s default policy: %v", direction, err)
	}
	fmt.Printf("Set %s default policy to %s\n", direction, policy)
	return nil
}

// processRules populates the specified eBPF map with rules
func processRules(rules []FirewallRule, ruleMap *ebpf.Map, direction string, ifaceName string) error {
	fmt.Printf("Loading %d %s rules for interface %s...\n", len(rules), direction, ifaceName)
	for i, rule := range rules {
		fmt.Printf("Processing %s rule %d: %s %s:%v (%s)\n",
			direction, i+1, rule.Protocol, rule.IP, rule.Port, rule.Action)

		var value RuleValue
		if len(rule.RuleName) > len(value.RuleName) {
			return fmt.Errorf("rule_name too long in %s rule %s: %s", direction, rule.RuleName, rule.RuleName)
		}
		if len(rule.Action) > len(value.Action) {
			return fmt.Errorf("action too long in %s rule %s: %s", direction, rule.RuleName, rule.Action)
		}
		if len(rule.Protocol) > len(value.Protocol) {
			return fmt.Errorf("protocol too long in %s rule %s: %s", direction, rule.RuleName, rule.Protocol)
		}
		if len(rule.Description) > len(value.Description) {
			return fmt.Errorf("description too long in %s rule %s: %s", direction, rule.RuleName, rule.Description)
		}
		copy(value.RuleName[:], []byte(rule.RuleName))
		copy(value.Action[:], []byte(strings.ToLower(rule.Action)))
		protocol := strings.ToLower(rule.Protocol)
		copy(value.Protocol[:], []byte(protocol))
		ipStr, err := parseIPWithCIDR(rule.IP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing IP in %s rule %s: %v\n", direction, rule.RuleName, err)
			continue
		}
		if len(ipStr) > len(value.IP) {
			fmt.Fprintf(os.Stderr, "IP too long in %s rule %s: %s\n", direction, rule.RuleName, ipStr)
			continue
		}
		copy(value.IP[:], []byte(ipStr))

		// Skip port parsing for ICMP
		if protocol == "icmp" {
			if rule.Port != "" || rule.PortRange != nil {
				fmt.Fprintf(os.Stderr, "Error: port or port_range specified for ICMP in %s rule %s\n", direction, rule.RuleName)
				continue
			}
			value.HasPortRange = 0
			*(*int32)(unsafe.Pointer(&value.PortInfo[0])) = 0
		} else if rule.PortRange != nil {
			if rule.Port != "" {
				fmt.Fprintf(os.Stderr, "Error: both port and port_range specified in %s rule %s\n", direction, rule.RuleName)
				continue
			}
			if rule.PortRange.Start < 0 || rule.PortRange.End > 65535 || rule.PortRange.Start > rule.PortRange.End {
				fmt.Fprintf(os.Stderr, "Invalid port range in %s rule %s: %d-%d\n", direction, rule.RuleName, rule.PortRange.Start, rule.PortRange.End)
				continue
			}
			value.HasPortRange = 1
			*(*int32)(unsafe.Pointer(&value.PortInfo[0])) = rule.PortRange.Start
			*(*int32)(unsafe.Pointer(&value.PortInfo[4])) = rule.PortRange.End
		} else {
			port, err := parsePort(rule.Port)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing port in %s rule %s: %v\n", direction, rule.RuleName, err)
				continue
			}
			value.HasPortRange = 0
			*(*int32)(unsafe.Pointer(&value.PortInfo[0])) = port
		}
		copy(value.Description[:], []byte(rule.Description))

		key := RuleKey(i)
		if err := ruleMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating %s map for rule %s: %v\n", direction, rule.RuleName, err)
			continue
		}
		fmt.Printf("  ✓ Added %s rule %s at index %d\n", direction, rule.RuleName, i)
	}
	return nil
}

func main() {
	// Remove MEMLOCK limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) < 3 {
		fmt.Println("Usage: sudo ./firewall <interface> <config.yaml>")
		os.Exit(1)
	}

	ifaceName := os.Args[1]
	config, err := loadConfig(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Load both eBPF specs generated by bpf2go
	inboundSpec, err := LoadInboundBPF()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading inbound eBPF spec: %v\n", err)
		os.Exit(1)
	}
	outboundSpec, err := LoadOutboundBPF()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading outbound eBPF spec: %v\n", err)
		os.Exit(1)
	}

	// Merge outbound maps and programs into inbound spec
	for name, m := range outboundSpec.Maps {
		inboundSpec.Maps[name] = m
	}
	for name, p := range outboundSpec.Programs {
		inboundSpec.Programs[name] = p
	}
	spec := inboundSpec

	// Debug: Print available maps and programs
	fmt.Println("Available maps:")
	for name := range spec.Maps {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println("Available programs:")
	for name := range spec.Programs {
		fmt.Printf("  - %s\n", name)
	}

	// Check required maps
	requiredMaps := []string{"inbound_rules", "inbound_default_policy", "outbound_rules", "outbound_default_policy"}
	for _, mapName := range requiredMaps {
		if spec.Maps[mapName] == nil {
			fmt.Fprintf(os.Stderr, "Error: required map '%s' not found in eBPF spec\n", mapName)
			os.Exit(1)
		}
	}

	// Check required programs
	requiredProgs := []string{"xdp_firewall_inbound", "tc_firewall_outbound"}
	for _, progName := range requiredProgs {
		if spec.Programs[progName] == nil {
			fmt.Fprintf(os.Stderr, "Error: required program '%s' not found in eBPF spec\n", progName)
			os.Exit(1)
		}
	}

	// Load eBPF collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading eBPF collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	// Get maps from collection
	inboundMap := coll.Maps["inbound_rules"]
	inboundDefaultMap := coll.Maps["inbound_default_policy"]
	outboundMap := coll.Maps["outbound_rules"]
	outboundDefaultMap := coll.Maps["outbound_default_policy"]

	// Get interface
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting interface %s: %v\n", ifaceName, err)
		os.Exit(1)
	}

	// Get programs from collection
	inboundProg := coll.Programs["xdp_firewall_inbound"]
	if inboundProg == nil {
		fmt.Fprintf(os.Stderr, "Error: inbound program not found in collection\n")
		os.Exit(1)
	}
	outboundProg := coll.Programs["tc_firewall_outbound"]
	if outboundProg == nil {
		fmt.Fprintf(os.Stderr, "Error: outbound program not found in collection\n")
		os.Exit(1)
	}

	// Attach inbound program (XDP)
	xdpOptions := link.XDPOptions{
		Program:   inboundProg,
		Interface: ifaceLink.Attrs().Index,
		Flags:     link.XDPGenericMode,
	}
	xdpLink, err := link.AttachXDP(xdpOptions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error attaching XDP program to %s: %v\n", ifaceName, err)
		progFD := inboundProg.FD()
		if progFD < 0 {
			fmt.Fprintf(os.Stderr, "Invalid BPF program file descriptor\n")
			os.Exit(1)
		}
		err = netlink.LinkSetXdpFd(ifaceLink, progFD)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach XDP program to interface %s: %v\n", ifaceName, err)
			os.Exit(1)
		}
		fmt.Printf("Successfully attached XDP program (netlink fallback) to %s\n", ifaceName)
	} else {
		defer xdpLink.Close()
		fmt.Printf("Successfully attached XDP program to %s\n", ifaceName)
	}

	// Attach outbound program (TC)
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !strings.Contains(err.Error(), "file exists") {
		fmt.Fprintf(os.Stderr, "Error adding qdisc to %s: %v\n", ifaceName, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           outboundProg.FD(),
		Name:         "tc_firewall_outbound",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		fmt.Fprintf(os.Stderr, "Error attaching TC program to %s: %v\n", ifaceName, err)
	} else {
		fmt.Printf("Successfully attached TC program to %s\n", ifaceName)
	}

	// Set default policies
	if err := setDefaultPolicy(inboundDefaultMap, config.InboundPolicy, "inbound"); err != nil {
		os.Exit(1)
	}
	if err := setDefaultPolicy(outboundDefaultMap, config.OutboundPolicy, "outbound"); err != nil {
		os.Exit(1)
	}

	// Process inbound and outbound rules
	if err := processRules(config.Inbound, inboundMap, "inbound", ifaceName); err != nil {
		fmt.Fprintf(os.Stderr, "Error processing inbound rules: %v\n", err)
		os.Exit(1)
	}
	if err := processRules(config.Outbound, outboundMap, "outbound", ifaceName); err != nil {
		fmt.Fprintf(os.Stderr, "Error processing outbound rules: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Firewall rules applied to interface %s\n", ifaceName)
	fmt.Println("Firewall is running. Press Ctrl+C to stop.")
	select {}
}