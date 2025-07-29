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
	Start uint16 `yaml:"start"`
	End   uint16 `yaml:"end"`
}

// FirewallRule represents the firewall_rule_t struct for YAML parsing
type FirewallRule struct {
	RuleName    string     `yaml:"rule_name"`
	Action      string     `yaml:"action"`
	Protocol    string     `yaml:"protocol"`
	IP          string     `yaml:"ip"`
	PortRange   *PortRange `yaml:"port_range"` // Used for parsing
	Port        string     `yaml:"port"`       // Used for parsing
	Description string     `yaml:"description"`
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

// FirewallConfig represents the top-level firewall configuration
type FirewallConfig struct {
	Inbound        []FirewallRule `yaml:"inbound"`
	Outbound       []FirewallRule `yaml:"outbound"`
	InboundPolicy  string        `yaml:"inbound_policy"`
	OutboundPolicy string        `yaml:"outbound_policy"`
}

// eBPF map structures
type RuleKey uint32 // Array index

func parseIPWithCIDR(ipStr string) (uint32, uint32, error) {
	if ipStr == "any" {
		return 0, 0, nil
	}
	if ip := net.ParseIP(ipStr); ip != nil {
		if ip.To4() == nil {
			return 0, 0, fmt.Errorf("only IPv4 is supported")
		}
		// Convert to uint32 (big-endian)
		ip4 := ip.To4()
		ipInt := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		return ipInt, 0xFFFFFFFF, nil // Single IP, full mask
	}
	_, ipNet, err := net.ParseCIDR(ipStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid IP/CIDR %s: %v", ipStr, err)
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return 0, 0, fmt.Errorf("only IPv4 CIDR is supported")
	}
	ipInt := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	ones, _ := ipNet.Mask.Size()
	mask := uint32((1<<uint(ones) - 1) << uint(32-ones))
	return ipInt, mask, nil
}

func parsePort(portStr string) (uint16, error) {
	if portStr == "" || portStr == "any" {
		return 0, nil
	}
	var port uint16
	_, err := fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port %s: %v", portStr, err)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port %s out of range (0-65535)", portStr)
	}
	return port, nil
}

func parseProtocol(protocolStr string) (uint16, error) {
	protocolStr = strings.ToLower(protocolStr)
	switch protocolStr {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	case "icmp":
		return unix.IPPROTO_ICMP, nil
	case "any":
		return 0, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", protocolStr)
	}
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
	defaultAction := uint8(0) // POLICY_DROP
	if strings.ToUpper(policy) == "ACCEPT" {
		defaultAction = 1 // POLICY_ACCEPT
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
        copy(value.RuleName[:], []byte(rule.RuleName))

        // Set action
        if strings.ToLower(rule.Action) == "allow" {
            value.Action = 1 // POLICY_ACCEPT
        } else if strings.ToLower(rule.Action) == "block" {
            value.Action = 0 // POLICY_DROP
        } else {
            fmt.Fprintf(os.Stderr, "Invalid action in %s rule %s: %s\n", direction, rule.RuleName, rule.Action)
            continue
        }

        // Set protocol
        protocolNum, err := parseProtocol(rule.Protocol)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error parsing protocol in %s rule %s: %v\n", direction, rule.RuleName, err)
            continue
        }
        value.Protocol = protocolNum

        // Set IP and netmask
        ipInt, mask, err := parseIPWithCIDR(rule.IP)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error parsing IP in %s rule %s: %v\n", direction, rule.RuleName, err)
            continue
        }
        value.IP = ipInt
        value.Netmask = mask

        // Handle port or port range
        if protocolNum == unix.IPPROTO_ICMP {
            if rule.Port != "" || rule.PortRange != nil {
                fmt.Fprintf(os.Stderr, "Error: port or port_range specified for ICMP in %s rule %s\n", direction, rule.RuleName)
                continue
            }
            value.HasPortRange = 0
            *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = 0
            *(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = 0
        } else if rule.PortRange != nil {
            if rule.Port != "" {
                fmt.Fprintf(os.Stderr, "Error: both port and port_range specified in %s rule %s\n", direction, rule.RuleName)
                continue
            }
            if rule.PortRange.Start > rule.PortRange.End || rule.PortRange.End > 65535 {
                fmt.Fprintf(os.Stderr, "Invalid port range in %s rule %s: %d-%d\n", direction, rule.RuleName, rule.PortRange.Start, rule.PortRange.End)
                continue
            }
            value.HasPortRange = 1
            *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = rule.PortRange.Start
            *(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = rule.PortRange.End
        } else {
            port, err := parsePort(rule.Port)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Error parsing port in %s rule %s: %v\n", direction, rule.RuleName, err)
                continue
            }
            value.HasPortRange = 0
            *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = port
            *(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = 0 // Clear second half
        }

        // Set used and enabled flags
        value.Used = 1
        value.Enabled = 1

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