package rules

import (
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"
	"syscall"

	"bytes"
	"encoding/binary"

	"firewall/config"
	"firewall/fwebpf"

	"github.com/cilium/ebpf"
	"github.com/fatih/color"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"gopkg.in/yaml.v2"
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

// TODO
// FirewallRuleToEBPF converts a FirewallRule to an eBPF RuleValue.
func FirewallRuleToEBPF(rule config.FirewallRule) (config.RuleValue, error) {
    var value config.RuleValue

    // Validate rule name length
    if len(rule.RuleName) > len(value.RuleName) {
        return value, fmt.Errorf("rule_name too long rule %s: %s", rule.RuleName, rule.RuleName)
    }
    copy(value.RuleName[:], []byte(rule.RuleName))

    // Set action
    if strings.ToLower(rule.Action) == "accept" {
        value.Action = config.POLICY_ACCEPT
    } else if strings.ToLower(rule.Action) == "drop" {
        value.Action = config.POLICY_DROP
    } else {
        return value, fmt.Errorf("invalid action rule %s: %s", rule.RuleName, rule.Action)
    }

    // Set protocol
    protocolNum, err := ParseProtocol(rule.Protocol)
    if err != nil {
        return value, fmt.Errorf("error parsing protocol rule %s: %v", rule.RuleName, err)
    }
    value.Protocol = protocolNum

    // Set IP and netmask
    ipInt, mask, err := ParseIPWithCIDR(rule.IP)
    if err != nil {
        return value, fmt.Errorf("error parsing IP in rule %s: %v", rule.RuleName, err)
    }
    value.IP = ipInt
    value.Netmask = mask

    // Handle port or port range
    if protocolNum == syscall.IPPROTO_ICMP { // or unix.IPPROTO_ICMP
        if rule.Port != "" || rule.PortRange != nil {
            return value, fmt.Errorf("error: port or port_range specified for ICMP rule %s", rule.RuleName)
        }
        value.HasPortRange = 0
        *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = 0
        *(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = 0
    } else if rule.PortRange != nil {
        if rule.Port != "" {
            return value, fmt.Errorf("error: both port and port_range specified in rule %s", rule.RuleName)
        }
        if rule.PortRange.Start > rule.PortRange.End || rule.PortRange.End > 65535 {
            return value, fmt.Errorf("invalid port range in rule %s: %d-%d", rule.RuleName, rule.PortRange.Start, rule.PortRange.End)
        }
        value.HasPortRange = 1
        *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = rule.PortRange.Start
        *(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = rule.PortRange.End
    } else {
        port, err := ParsePort(rule.Port)
        if err != nil {
            return value, fmt.Errorf("error parsing port in rule %s: %v", rule.RuleName, err)
        }
        value.HasPortRange = 0
        *(*uint16)(unsafe.Pointer(&value.PortInfo[0])) = port
        *(*uint16)(unsafe.Pointer(&value.PortInfo[2])) = 0 // Clear second half
    }

    // Set used and enabled flags
    value.Used = 1
    value.Enabled = 1

    return value, nil
}

// ProcessRules populates the specified eBPF map with rules
func ProcessRules(rules []config.FirewallRule, ruleMap *ebpf.Map, ifaceName string) error {
	info("Loading %d rules for interface %s...\n", len(rules), ifaceName)
	for i, rule := range rules {
		bvalue, err := FirewallRuleToEBPF(rule)
		if err == nil {
			key := config.RuleKey(i)
			if err := ruleMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&bvalue), ebpf.UpdateAny); err != nil {
				errPrint(os.Stderr, "Error updating map for rule %s: %v\n", rule.RuleName, err)
				continue
			}
			success("  ✓ Added %s rule at index %d\n", rule.RuleName, i)
		} else {
			// error("  ✓ Added %s rule %s at index %d\n", direction, rule.RuleName, i)
		}
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

	// Define ANSI color codes
	const red = "\033[31m"
	const green = "\033[32m"
	const reset = "\033[0m"

	/*
	// Print defqult inbound policy
	inboundDefaultMap := coll.Maps["inbound_default_policy"]
	var defaultKey config.RuleKey
	var defaultAction uint8
	if err := inboundDefaultMap.Lookup(&defaultKey, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == config.POLICY_ACCEPT {
			policy = "ACCEPT"
		}
		info("Inbound Default Policy: %s\n", policy)
	} else {
		info("Inbound Default Policy: not set\n")
	}
	// Print default outbound policy
	outboundDefaultMap := coll.Maps["outbound_default_policy"]
	if err := outboundDefaultMap.Lookup(&defaultKey, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == config.POLICY_ACCEPT {
			policy = "ACCEPT"
		}
		info("Outbound Default Policy: %s\n", policy)
	} else {
		info("Outbound Default Policy: not set\n")
	}
	*/

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
		action := red + "DROP" + reset
		if value.Action == config.POLICY_ACCEPT {
			action = green + "ACCEPT" + reset
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
		action := red + "DROP" + reset
		if value.Action == config.POLICY_ACCEPT {
			action = green + "ACCEPT" + reset
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
	key = 0
	var defaultAction uint8
	if err := inboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := red + "DROP" + reset
		if defaultAction == config.POLICY_ACCEPT {
			policy = green + "ACCEPT" + reset
		}
		info("\nInbound Default Policy: %s\n", policy)
	}

	outboundDefaultMap := coll.Maps["outbound_default_policy"]
	if err := outboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := red + "DROP" + reset
		if defaultAction == config.POLICY_ACCEPT {
			policy = green + "ACCEPT" + reset
		}
		info("\nOutbound Default Policy: %s\n", policy)
	}

	return nil
}


// AUDIT UTILS
// ReverseProcessRules converts RuleValue structs from an eBPF map back into FirewallRule structs
func ConvertBinaryRuleToFirewallRule(value config.RuleValue) (config.FirewallRule, error) {
	var rule config.FirewallRule

	// for key, value := range ruleValues {
		// if value.Used == 0 || value.Enabled == 0 {
			// continue // Skip unused or disabled rules
		// }

		// var rule config.FirewallRule

		// Extract rule name (convert [128]byte to string, trimming null bytes)
		ruleName := string(value.RuleName[:])
		rule.RuleName = strings.TrimRight(ruleName, "\x00")
		// if rule.RuleName == "" {
		// 	return rule, fmt.Errorf("invalid empty rule name")
		// }

		// Convert action
		switch value.Action {
		case config.POLICY_ACCEPT: // POLICY_ACCEPT
			rule.Action = "ACCEPT"
		case config.POLICY_DROP: // POLICY_DROP
			rule.Action = "DROP"
		default:
			return rule, fmt.Errorf("invalid action value %d in rule %s", value.Action, rule.RuleName)
		}

		// Convert protocol
		protocol, err := ReverseParseProtocol(value.Protocol)
		if err != nil {
			return rule, fmt.Errorf("error reversing protocol in rule %s: %v", rule.RuleName, err)
		}
		rule.Protocol = protocol

		// Convert IP and netmask
		ipStr, err := ReverseParseIPWithCIDR(value.IP, value.Netmask)
		if err != nil {
			return rule, fmt.Errorf("error reversing IP in rule %s: %v", rule.RuleName, err)
		}
		rule.IP = ipStr

		// Convert port or port range
		if value.Protocol == syscall.IPPROTO_ICMP {
			if value.HasPortRange != 0 || value.PortInfo[0] != 0 || value.PortInfo[2] != 0 {
				return rule, fmt.Errorf("invalid port/port range data for ICMP in rule %s", rule.RuleName)
			}
			rule.Port = ""
			rule.PortRange = nil
		} else if value.HasPortRange == 1 {
			start := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
			end := *(*uint16)(unsafe.Pointer(&value.PortInfo[2]))
			if start > end || end > 65535 {
				return rule, fmt.Errorf("invalid port range %d-%d in rule %s", start, end, rule.RuleName)
			}
			rule.PortRange = &config.PortRange{
				Start: start,
				End:   end,
			}
			rule.Port = ""
		} else {
			port := *(*uint16)(unsafe.Pointer(&value.PortInfo[0]))
			if port == 0 && value.PortInfo[2] != 0 {
				return rule, fmt.Errorf("invalid port data in rule %s", rule.RuleName)
			}
			if port != 0 {
				rule.Port = fmt.Sprintf("%d", port)
			} else {
				rule.Port = "any"
			}
			rule.PortRange = nil
		}

		// Description is not stored in RuleValue, so leave it empty
		rule.Description = ""

		// rules = append(rules, rule)
	// }

	return rule, nil
}

// ReverseParseProtocol converts a protocol number back to its string representation
func ReverseParseProtocol(protocol uint16) (string, error) {
	switch protocol {
	case syscall.IPPROTO_TCP:
		return "tcp", nil
	case syscall.IPPROTO_UDP:
		return "udp", nil
	case syscall.IPPROTO_ICMP:
		return "icmp", nil
	default:
		return "any", nil
	}
}

// ReverseParseIPWithCIDR converts IP and netmask back to CIDR notation
func ReverseParseIPWithCIDR(ip, netmask uint32) (string, error) {
	// Convert uint32 IP to net.IP
	ipBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		ipBytes[i] = byte(ip >> (24 - 8*i))
	}
	netIP := net.IP(ipBytes).To4()
	if netIP == nil {
		return "", fmt.Errorf("invalid IP address: %d", ip)
	}

	// Convert uint32 netmask to net.IPMask
	maskBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		maskBytes[i] = byte(netmask >> (24 - 8*i))
	}
	ipMask := net.IPMask(maskBytes)

	// Get CIDR prefix length
	ones, bits := ipMask.Size()
	if ones == 0 && netmask != 0 {
		return "", fmt.Errorf("invalid netmask: %d", netmask)
	}
	if bits != 32 {
		return "", fmt.Errorf("invalid netmask bits: %d", bits)
	}

	return fmt.Sprintf("%s/%d", netIP.String(), ones), nil
}

// SerializeFirewallRules serializes a slice of FirewallRule structs to YAML
func SerializeFirewallRules(rule config.FirewallRule) (string, error) {
	// Serialize to YAML
	yamlData, err := yaml.Marshal(&rule)
	if err != nil {
		return "", fmt.Errorf("error marshaling to YAML: %v", err)
	}
	return string(yamlData), nil
}

// GetBinaryRepresentation returns the binary representation of RuleValue excluding RuleName, Used, and Enabled
func GetRuleBinarySignature(rv config.RuleValue) ([]byte, error) {
	// Create a buffer to store binary data
	var buf bytes.Buffer

	// Write the entire struct to the buffer using binary encoding (big-endian)
	if err := binary.Write(&buf, binary.BigEndian, rv); err != nil {
		return nil, fmt.Errorf("failed to encode struct to binary: %w", err)
	}

	// Calculate offsets and sizes
	const (
		ruleNameSize = 128              // Size of RuleName ([128]byte)
		usedSize     = 1                // Size of Used (uint8)
		enabledSize  = 1                // Size of Enabled (uint8)
		totalTrim    = ruleNameSize + usedSize + enabledSize
	)

	// Get the full byte array
	data := buf.Bytes()

	// Ensure the buffer is large enough
	if len(data) < totalTrim {
		return nil, fmt.Errorf("binary data too short: got %d bytes, expected at least %d", len(data), totalTrim)
	}

	// Trim RuleName (start) and Used+Enabled (end)
	return data[ruleNameSize : len(data)-usedSize-enabledSize], nil
}

// ParseRuleBinarySignature reconstructs a config.RuleValue from its binary signature.
// The input is the binary data produced by GetRuleBinarySignature, which excludes
// RuleName ([128]byte), Used (uint8), and Enabled (uint8). The reconstructed struct
// has zero values for these fields.
func ParseRuleBinarySignature(data []byte, expectedTrimmedSize int) (config.RuleValue, error) {
	// Constants for trimmed fields
	const (
		ruleNameSize = 128 // Size of RuleName ([128]byte)
		usedSize     = 1   // Size of Used (uint8)
		enabledSize  = 1   // Size of Enabled (uint8)
		totalTrim    = ruleNameSize + usedSize + enabledSize
	)

	// Validate input size
	if len(data) != expectedTrimmedSize {
		return config.RuleValue{}, fmt.Errorf("invalid binary data length: got %d bytes, expected %d", len(data), expectedTrimmedSize)
	}

	// Create a buffer for the full struct
	var rv config.RuleValue
	var buf bytes.Buffer

	// Write RuleName (zero-filled, 128 bytes)
	var ruleName [128]byte
	if _, err := buf.Write(ruleName[:]); err != nil {
		return config.RuleValue{}, fmt.Errorf("failed to write RuleName: %w", err)
	}

	// Write the input data (non-trimmed fields)
	if _, err := buf.Write(data); err != nil {
		return config.RuleValue{}, fmt.Errorf("failed to write rule data: %w", err)
	}

	// Write Used and Enabled (zero-filled, 1 byte each)
	if err := buf.WriteByte(0); err != nil {
		return config.RuleValue{}, fmt.Errorf("failed to write Used: %w", err)
	}
	if err := buf.WriteByte(0); err != nil {
		return config.RuleValue{}, fmt.Errorf("failed to write Enabled: %w", err)
	}

	// Decode the full buffer into the struct
	if err := binary.Read(&buf, binary.BigEndian, &rv); err != nil {
		return config.RuleValue{}, fmt.Errorf("failed to decode binary to struct: %w", err)
	}

	return rv, nil
}

func RetrieveFirewallBinaryRules(ifaceName string, mapName string) ([]config.RuleValue, error) {
	var binaryRules []config.RuleValue

	// Check if programs are attached
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return binaryRules, fmt.Errorf("getting interface %s: %v", ifaceName, err)
	}

	xdpAttached := false
	if ifaceLink.Attrs().Xdp != nil && ifaceLink.Attrs().Xdp.Attached {
		xdpAttached = true
	}

	// filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
	// if err != nil {
	// 	return binaryRules, fmt.Errorf("listing filters on %s: %v", ifaceName, err)
	// }
	// tcAttached := false
	// for _, f := range filters {
	// 	if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_firewall_outbound" {
	// 		tcAttached = true
	// 		break
	// 	}
	// }

	if !xdpAttached {
		errPrint(os.Stderr, "eBPF programs not fully attached to interface %s\n", ifaceName)
		os.Exit(1)
	}

	// Load pinned maps
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName
	coll, err := fwebpf.LoadPinnedCollection(bpfFsPath)
	if err != nil {
		return binaryRules, fmt.Errorf("loading pinned eBPF objects from %s: %v", bpfFsPath, err)
	}
	defer coll.Close()

	// Fetch map rules
	inboundMap := coll.Maps[mapName]
	var key config.RuleKey
	var value config.RuleValue
	iter := inboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}
		binaryRules = append(binaryRules, value)
	}

	return binaryRules, nil
}

func GetDefaultPolicy(ifaceName string, mapName string) (string, error) {

	var retValue string

	// Check if programs are attached
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return retValue, fmt.Errorf("getting interface %s: %v", ifaceName, err)
	}

	xdpAttached := false
	if ifaceLink.Attrs().Xdp != nil && ifaceLink.Attrs().Xdp.Attached {
		xdpAttached = true
	}

	// filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
	// if err != nil {
	// 	return retValue, fmt.Errorf("listing filters on %s: %v", ifaceName, err)
	// }
	// tcAttached := false
	// for _, f := range filters {
	// 	if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_firewall_outbound" {
	// 		tcAttached = true
	// 		break
	// 	}
	// }

	if !xdpAttached {
		errPrint(os.Stderr, "eBPF programs not fully attached to interface %s\n", ifaceName)
		os.Exit(1)
	}

	// Load pinned maps
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName
	coll, err := fwebpf.LoadPinnedCollection(bpfFsPath)
	if err != nil {
		return retValue, fmt.Errorf("loading pinned eBPF objects from %s: %v", bpfFsPath, err)
	}
	defer coll.Close()

	// Fetch map rules
	inboundMap := coll.Maps[mapName]
	var key config.RuleKey
	var value uint8
	iter := inboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value == config.POLICY_DROP {
			retValue = "DROP"
		} else if value == config.POLICY_ACCEPT {
			retValue = "ACCEPT"
		}
		break;
	}

	return retValue, nil

}

func RetrieveFirewallConfig(ifaceName string) (config.FirewallConfig, error) {

	// Prepare config struct
	var ifaceConfig config.FirewallConfig

	// Check if programs are attached
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return ifaceConfig, fmt.Errorf("getting interface %s: %v", ifaceName, err)
	}

	xdpAttached := false
	if ifaceLink.Attrs().Xdp != nil && ifaceLink.Attrs().Xdp.Attached {
		xdpAttached = true
	}

	// filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
	// if err != nil {
	// 	return ifaceConfig, fmt.Errorf("listing filters on %s: %v", ifaceName, err)
	// }
	// tcAttached := false
	// for _, f := range filters {
	// 	if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_firewall_outbound" {
	// 		tcAttached = true
	// 		break
	// 	}
	// }

	if !xdpAttached {
		errPrint(os.Stderr, "eBPF programs not fully attached to interface %s\n", ifaceName)
		os.Exit(1)
	}

	// Load pinned maps
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName
	coll, err := fwebpf.LoadPinnedCollection(bpfFsPath)
	if err != nil {
		return ifaceConfig, fmt.Errorf("loading pinned eBPF objects from %s: %v", bpfFsPath, err)
	}
	defer coll.Close()

	// Fetch inbound
	inboundMap := coll.Maps["inbound_rules"]
	var key config.RuleKey
	var value config.RuleValue
	iter := inboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}

		testr, err := ConvertBinaryRuleToFirewallRule(value)
		if err != nil {
			return ifaceConfig, fmt.Errorf("Reversing: %v", err)
		} else {
			ifaceConfig.Inbound = append(ifaceConfig.Inbound, testr)
		}
	}

	// Fetch outbound
	outboundMap := coll.Maps["outbound_rules"]
	iter = outboundMap.Iterate()
	for iter.Next(&key, &value) {

		if value.Used == 0 || value.Enabled == 0 {
			continue
		}

		testr, err := ConvertBinaryRuleToFirewallRule(value)
		if err != nil {
			return ifaceConfig, fmt.Errorf("Reversing: %v", err)
		} else {
			ifaceConfig.Outbound = append(ifaceConfig.Outbound, testr)
		}
	}

	// Compare default policies
	inboundDefaultMap := coll.Maps["inbound_default_policy"]
	var defaultAction uint8
	key = 0
	if err := inboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == 1 {
			policy = "ACCEPT"
		}
		ifaceConfig.InboundPolicy = policy
	} else {
		return ifaceConfig, fmt.Errorf("loading inbound default policy from %s: %v", ifaceName, err)
	}
	
	outboundDefaultMap := coll.Maps["outbound_default_policy"]
	if err := outboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == 1 {
			policy = "ACCEPT"
		}
		ifaceConfig.OutboundPolicy = policy
	} else {
		return ifaceConfig, fmt.Errorf("loading outbound default policy from %s: %v", ifaceName, err)
	}

	strRet, _ := config.SerializeFirewallConfig(ifaceConfig)
	fmt.Println(strRet)

	return ifaceConfig, nil
}
