package rules

import (
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"

	"firewall/config"
	"firewall/fwebpf"

	"github.com/cilium/ebpf"
	"github.com/fatih/color"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Initialize colored output
var (
	info     = color.New(color.FgBlue).PrintfFunc()
	success  = color.New(color.FgGreen).PrintfFunc()
	errPrint = color.New(color.FgRed).FprintfFunc()
)

// ParseIPWithCIDR converts an IP or CIDR string to uint32 IP and netmask
func ParseIPWithCIDR(ipStr string) (uint32, uint32, error) {
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
	mask := uint32((1<<uint(ones)-1)<<uint(32-ones))
	return ipInt, mask, nil
}

// ParsePort converts a port string to uint16
func ParsePort(portStr string) (uint16, error) {
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

// ParseProtocol converts a protocol string to uint16
func ParseProtocol(protocolStr string) (uint16, error) {
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

// SetDefaultPolicy updates the default policy map with the specified policy
func SetDefaultPolicy(policyMap *ebpf.Map, policy string, direction string) error {
	var defaultKey uint32 = 0
	defaultAction := uint8(0) // POLICY_DROP
	if strings.ToUpper(policy) == "ACCEPT" {
		defaultAction = 1 // POLICY_ACCEPT
	}
	if err := policyMap.Update(unsafe.Pointer(&defaultKey), unsafe.Pointer(&defaultAction), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("error setting %s default policy: %v", direction, err)
	}
	success("Set %s default policy to %s\n", direction, policy)
	return nil
}

// ProcessRules populates the specified eBPF map with rules
func ProcessRules(rules []config.FirewallRule, ruleMap *ebpf.Map, direction string, ifaceName string) error {
	info("Loading %d %s rules for interface %s...\n", len(rules), direction, ifaceName)
	for i, rule := range rules {
		info("Processing %s rule %d: %s %s:%v (%s)\n",
			direction, i+1, rule.Protocol, rule.IP, rule.Port, rule.Action)

		var value config.RuleValue
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
			errPrint(os.Stderr, "Invalid action in %s rule %s: %s\n", direction, rule.RuleName, rule.Action)
			continue
		}

		// Set protocol
		protocolNum, err := ParseProtocol(rule.Protocol)
		if err != nil {
			errPrint(os.Stderr, "Error parsing protocol in %s rule %s: %v\n", direction, rule.RuleName, err)
			continue
		}
		value.Protocol = protocolNum

		// Set IP and netmask
		ipInt, mask, err := ParseIPWithCIDR(rule.IP)
		if err != nil {
			errPrint(os.Stderr, "Error parsing IP in %s rule %s: %v\n", direction, rule.RuleName, err)
			continue
		}
		value.IP = ipInt
		value.Netmask = mask

		// Handle port or port range
		if protocolNum == unix.IPPROTO_ICMP {
			if rule.Port != "" || rule.PortRange != nil {
				errPrint(os.Stderr, "Error: port or port_range specified for ICMP in %s rule %s\n", direction, rule.RuleName)
				continue
			}
			value.HasPortRange = 0
			*(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = 0
			*(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = 0
		} else if rule.PortRange != nil {
			if rule.Port != "" {
				errPrint(os.Stderr, "Error: both port and port_range specified in %s rule %s\n", direction, rule.RuleName)
				continue
			}
			if rule.PortRange.Start > rule.PortRange.End || rule.PortRange.End > 65535 {
				errPrint(os.Stderr, "Invalid port range in %s rule %s: %d-%d\n", direction, rule.RuleName, rule.PortRange.Start, rule.PortRange.End)
				continue
			}
			value.HasPortRange = 1
			*(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = rule.PortRange.Start
			*(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = rule.PortRange.End
		} else {
			port, err := ParsePort(rule.Port)
			if err != nil {
				errPrint(os.Stderr, "Error parsing port in %s rule %s: %v\n", direction, rule.RuleName, err)
				continue
			}
			value.HasPortRange = 0
			*(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = port
			*(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = 0 // Clear second half
		}

		// Set used and enabled flags
		value.Used = 1
		value.Enabled = 1

		key := config.RuleKey(i)
		if err := ruleMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny); err != nil {
			errPrint(os.Stderr, "Error updating %s map for rule %s: %v\n", direction, rule.RuleName, err)
			continue
		}
		success("  ✓ Added %s rule %s at index %d\n", direction, rule.RuleName, i)
	}
	return nil
}

// PrintRules prints the currently applied rules on the interface
func PrintRules(ifaceName string) error {
	// Check if programs are attached
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting interface %s: %v", ifaceName, err)
	}

	xdpAttached := false
	if ifaceLink.Attrs().Xdp != nil && ifaceLink.Attrs().Xdp.Attached {
		xdpAttached = true
	}

	filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("listing filters on %s: %v", ifaceName, err)
	}
	tcAttached := false
	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_firewall_outbound" {
			tcAttached = true
			break
		}
	}

	if !xdpAttached && !tcAttached {
		info("No eBPF programs attached to interface %s\n", ifaceName)
		return nil
	}

	// Load pinned maps
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName
	coll, err := fwebpf.LoadPinnedCollection(bpfFsPath)
	if err != nil {
		return fmt.Errorf("loading pinned eBPF objects from %s: %v", bpfFsPath, err)
	}
	defer coll.Close()

	// Print inbound rules
	inboundMap := coll.Maps["inbound_rules"]
	info("Inbound Rules:\n")
	var key config.RuleKey
	var value config.RuleValue
	iter := inboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}
		ruleName := strings.TrimRight(string(value.RuleName[:]), "\x00")
		action := "BLOCK"
		if value.Action == 1 {
			action = "ALLOW"
		}
		protocol := "any"
		switch value.Protocol {
		case unix.IPPROTO_TCP:
			protocol = "tcp"
		case unix.IPPROTO_UDP:
			protocol = "udp"
		case unix.IPPROTO_ICMP:
			protocol = "icmp"
		}
		ip := "any"
		if value.IP != 0 {
			ip = fmt.Sprintf("%d.%d.%d.%d", value.IP>>24, (value.IP>>16)&0xFF, (value.IP>>8)&0xFF, value.IP&0xFF)
			if value.Netmask != 0xFFFFFFFF {
				ones := 0
				for mask := value.Netmask; mask != 0; mask >>= 1 {
					ones += int(mask & 1)
				}
				ip += fmt.Sprintf("/%d", ones)
			}
		}
		var port string
		if value.HasPortRange == 1 {
			start := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
			end := *(*uint16)(unsafe.Pointer(&value.PortInfo[2]))
			port = fmt.Sprintf("%d-%d", start, end)
		} else if value.Protocol != unix.IPPROTO_ICMP {
			portNum := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
			if portNum != 0 {
				port = fmt.Sprintf("%d", portNum)
			} else {
				port = "any"
			}
		} else {
			port = "n/a"
		}
		fmt.Printf("  Rule %s: %s %s %s:%s\n", ruleName, protocol, ip, port, action)
	}

	// Print outbound rules
	outboundMap := coll.Maps["outbound_rules"]
	info("\nOutbound Rules:\n")
	iter = outboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}
		ruleName := strings.TrimRight(string(value.RuleName[:]), "\x00")
		action := "BLOCK"
		if value.Action == 1 {
			action = "ALLOW"
		}
		protocol := "any"
		switch value.Protocol {
		case unix.IPPROTO_TCP:
			protocol = "tcp"
		case unix.IPPROTO_UDP:
			protocol = "udp"
		case unix.IPPROTO_ICMP:
			protocol = "icmp"
		}
		ip := "any"
		if value.IP != 0 {
			ip = fmt.Sprintf("%d.%d.%d.%d", value.IP>>24, (value.IP>>16)&0xFF, (value.IP>>8)&0xFF, value.IP&0xFF)
			if value.Netmask != 0xFFFFFFFF {
				ones := 0
				for mask := value.Netmask; mask != 0; mask >>= 1 {
					ones += int(mask & 1)
				}
				ip += fmt.Sprintf("/%d", ones)
			}
		}
		var port string
		if value.HasPortRange == 1 {
			start := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
			end := *(*uint16)(unsafe.Pointer(&value.PortInfo[2]))
			port = fmt.Sprintf("%d-%d", start, end)
		} else if value.Protocol != unix.IPPROTO_ICMP {
			portNum := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
			if portNum != 0 {
				port = fmt.Sprintf("%d", portNum)
			} else {
				port = "any"
			}
		} else {
			port = "n/a"
		}
		fmt.Printf("  Rule %s: %s %s %s:%s\n", ruleName, protocol, ip, port, action)
	}

	// Print default policies
	inboundDefaultMap := coll.Maps["inbound_default_policy"]
	var defaultAction uint8
	if err := inboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == 1 {
			policy = "ACCEPT"
		}
		info("\nInbound Default Policy: %s\n", policy)
	}
	outboundDefaultMap := coll.Maps["outbound_default_policy"]
	if err := outboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == 1 {
			policy = "ACCEPT"
		}
		info("\nOutbound Default Policy: %s\n", policy)
	}

	return nil
}

// AuditRules compares YAML rules with currently applied rules
func AuditRules(ifaceName, configPath string) error {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %v", err)
	}

	// Check if programs are attached
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting interface %s: %v", ifaceName, err)
	}

	xdpAttached := false
	if ifaceLink.Attrs().Xdp != nil && ifaceLink.Attrs().Xdp.Attached {
		xdpAttached = true
	}

	filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("listing filters on %s: %v", ifaceName, err)
	}
	tcAttached := false
	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_firewall_outbound" {
			tcAttached = true
			break
		}
	}

	if !xdpAttached || !tcAttached {
		errPrint(os.Stderr, "eBPF programs not fully attached to interface %s\n", ifaceName)
		os.Exit(1)
	}

	// Load pinned maps
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName
	coll, err := fwebpf.LoadPinnedCollection(bpfFsPath)
	if err != nil {
		return fmt.Errorf("loading pinned eBPF objects from %s: %v", bpfFsPath, err)
	}
	defer coll.Close()

	// Compare inbound rules
	inboundMap := coll.Maps["inbound_rules"]
	var key config.RuleKey
	var value config.RuleValue
	appliedInbound := make(map[string]config.RuleValue)
	iter := inboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}
		ruleName := strings.TrimRight(string(value.RuleName[:]), "\x00")
		appliedInbound[ruleName] = value
	}

	configInbound := make(map[string]config.FirewallRule)
	for _, rule := range cfg.Inbound {
		configInbound[rule.RuleName] = rule
	}

	differences := 0
	for ruleName, applied := range appliedInbound {
		configRule, exists := configInbound[ruleName]
		if !exists {
			errPrint(os.Stderr, "Inbound rule %s found in eBPF but not in config\n", ruleName)
			differences++
			continue
		}
		// Compare fields
		configAction := strings.ToLower(configRule.Action)
		appliedAction := "block"
		if applied.Action == 1 {
			appliedAction = "allow"
		}
		if configAction != appliedAction {
			errPrint(os.Stderr, "Inbound rule %s action mismatch: config=%s, applied=%s\n", ruleName, configRule.Action, appliedAction)
			differences++
		}
		configProto, _ := ParseProtocol(configRule.Protocol)
		if configProto != applied.Protocol {
			errPrint(os.Stderr, "Inbound rule %s protocol mismatch: config=%s, applied=%d\n", ruleName, configRule.Protocol, applied.Protocol)
			differences++
		}
		configIP, configMask, _ := ParseIPWithCIDR(configRule.IP)
		if configIP != applied.IP || configMask != applied.Netmask {
			errPrint(os.Stderr, "Inbound rule %s IP/mask mismatch: config=%s, applied=%d/%d\n", ruleName, configRule.IP, applied.IP, applied.Netmask)
			differences++
		}
		if configRule.PortRange != nil {
			if applied.HasPortRange != 1 {
				errPrint(os.Stderr, "Inbound rule %s port range mismatch: expected range, got single port\n", ruleName)
				differences++
			} else {
				start := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
				end := *(*uint16)(unsafe.Pointer(&value.PortInfo[2]))
				if configRule.PortRange.Start != start || configRule.PortRange.End != end {
					errPrint(os.Stderr, "Inbound rule %s port range mismatch: config=%d-%d, applied=%d-%d\n", ruleName, configRule.PortRange.Start, configRule.PortRange.End, start, end)
					differences++
				}
			}
		} else if configRule.Port != "" && configRule.Protocol != "icmp" {
			port, _ := ParsePort(configRule.Port)
			if applied.HasPortRange != 0 || *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) != port {
				errPrint(os.Stderr, "Inbound rule %s port mismatch: config=%s, applied=%d\n", ruleName, configRule.Port, *(*uint16)(unsafe.Pointer(&value.PortInfo[0])))
				differences++
			}
		}
		delete(configInbound, ruleName)
	}
	for ruleName := range configInbound {
		errPrint(os.Stderr, "Inbound rule %s found in config but not in eBPF\n", ruleName)
		differences++
	}

	// Compare outbound rules
	outboundMap := coll.Maps["outbound_rules"]
	appliedOutbound := make(map[string]config.RuleValue)
	iter = outboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}
		ruleName := strings.TrimRight(string(value.RuleName[:]), "\x00")
		appliedOutbound[ruleName] = value
	}

	configOutbound := make(map[string]config.FirewallRule)
	for _, rule := range cfg.Outbound {
		configOutbound[rule.RuleName] = rule
	}

	for ruleName, applied := range appliedOutbound {
		configRule, exists := configOutbound[ruleName]
		if !exists {
			errPrint(os.Stderr, "Outbound rule %s found in eBPF but not in config\n", ruleName)
			differences++
			continue
		}
		// Compare fields
		configAction := strings.ToLower(configRule.Action)
		appliedAction := "block"
		if applied.Action == 1 {
			appliedAction = "allow"
		}
		if configAction != appliedAction {
			errPrint(os.Stderr, "Outbound rule %s action mismatch: config=%s, applied=%s\n", ruleName, configRule.Action, appliedAction)
			differences++
		}
		configProto, _ := ParseProtocol(configRule.Protocol)
		if configProto != applied.Protocol {
			errPrint(os.Stderr, "Outbound rule %s protocol mismatch: config=%s, applied=%d\n", ruleName, configRule.Protocol, applied.Protocol)
			differences++
		}
		configIP, configMask, _ := ParseIPWithCIDR(configRule.IP)
		if configIP != applied.IP || configMask != applied.Netmask {
			errPrint(os.Stderr, "Outbound rule %s IP/mask mismatch: config=%s, applied=%d/%d\n", ruleName, configRule.IP, applied.IP, applied.Netmask)
			differences++
		}
		if configRule.PortRange != nil {
			if applied.HasPortRange != 1 {
				errPrint(os.Stderr, "Outbound rule %s port range mismatch: expected range, got single port\n", ruleName)
				differences++
			} else {
				start := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
				end := *(*uint16)(unsafe.Pointer(&value.PortInfo[2]))
				if configRule.PortRange.Start != start || configRule.PortRange.End != end {
					errPrint(os.Stderr, "Outbound rule %s port range mismatch: config=%d-%d, applied=%d-%d\n", ruleName, configRule.PortRange.Start, configRule.PortRange.End, start, end)
					differences++
				}
			}
		} else if configRule.Port != "" && configRule.Protocol != "icmp" {
			port, _ := ParsePort(configRule.Port)
			if applied.HasPortRange != 0 || *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) != port {
				errPrint(os.Stderr, "Outbound rule %s port mismatch: config=%s, applied=%d\n", ruleName, configRule.Port, *(*uint16)(unsafe.Pointer(&value.PortInfo[0])))
				differences++
			}
		}
		delete(configOutbound, ruleName)
	}
	for ruleName := range configOutbound {
		errPrint(os.Stderr, "Outbound rule %s found in config but not in eBPF\n", ruleName)
		differences++
	}

	// Compare default policies
	inboundDefaultMap := coll.Maps["inbound_default_policy"]
	var defaultAction uint8
	if err := inboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == 1 {
			policy = "ACCEPT"
		}
		if strings.ToUpper(cfg.InboundPolicy) != policy {
			errPrint(os.Stderr, "Inbound default policy mismatch: config=%s, applied=%s\n", cfg.InboundPolicy, policy)
			differences++
		}
	}
	outboundDefaultMap := coll.Maps["outbound_default_policy"]
	if err := outboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == 1 {
			policy = "ACCEPT"
		}
		if strings.ToUpper(cfg.OutboundPolicy) != policy {
			errPrint(os.Stderr, "Outbound default policy mismatch: config=%s, applied=%s\n", cfg.OutboundPolicy, policy)
			differences++
		}
	}

	if differences > 0 {
		errPrint(os.Stderr, "Found %d differences between config and applied rules\n", differences)
		os.Exit(1)
	}
	success("No differences found between config and applied rules\n")
	return nil
}