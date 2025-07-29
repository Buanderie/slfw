package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/color"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" InboundBPF ./bpf/inbound.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" OutboundBPF ./bpf/outbound.c

// Initialize colored output
var (
	info     = color.New(color.FgBlue).PrintfFunc()
	success  = color.New(color.FgGreen).PrintfFunc()
	errPrint = color.New(color.FgRed).FprintfFunc()
)

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
	mask := uint32((1<<uint(ones)-1)<<uint(32-ones))
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
	success("Set %s default policy to %s\n", direction, policy)
	return nil
}

// processRules populates the specified eBPF map with rules
func processRules(rules []FirewallRule, ruleMap *ebpf.Map, direction string, ifaceName string) error {
	info("Loading %d %s rules for interface %s...\n", len(rules), direction, ifaceName)
	for i, rule := range rules {
		info("Processing %s rule %d: %s %s:%v (%s)\n",
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
			errPrint(os.Stderr, "Invalid action in %s rule %s: %s\n", direction, rule.RuleName, rule.Action)
			continue
		}

		// Set protocol
		protocolNum, err := parseProtocol(rule.Protocol)
		if err != nil {
			errPrint(os.Stderr, "Error parsing protocol in %s rule %s: %v\n", direction, rule.RuleName, err)
			continue
		}
		value.Protocol = protocolNum

		// Set IP and netmask
		ipInt, mask, err := parseIPWithCIDR(rule.IP)
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
			port, err := parsePort(rule.Port)
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

		key := RuleKey(i)
		if err := ruleMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny); err != nil {
			errPrint(os.Stderr, "Error updating %s map for rule %s: %v\n", direction, rule.RuleName, err)
			continue
		}
		success("  ✓ Added %s rule %s at index %d\n", direction, rule.RuleName, i)
	}
	return nil
}

// ensureBPFFilesystem ensures the BPF filesystem is mounted at /sys/fs/bpf
func ensureBPFFilesystem() error {
	bpfFsPath := "/sys/fs/bpf"
	// Check if /sys/fs/bpf exists
	if _, err := os.Stat(bpfFsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(bpfFsPath, 0755); err != nil {
			return fmt.Errorf("creating /sys/fs/bpf: %v", err)
		}
	}

	// Check if bpffs is mounted
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(bpfFsPath, &statfs); err != nil {
		return fmt.Errorf("checking BPF filesystem: %v", err)
	}
	if statfs.Type != unix.BPF_FS_MAGIC {
		// Attempt to mount bpffs
		if err := syscall.Mount("bpffs", bpfFsPath, "bpf", 0, ""); err != nil {
			return fmt.Errorf("mounting BPF filesystem at %s: %v (run 'sudo mount -t bpf bpffs /sys/fs/bpf')", bpfFsPath, err)
		}
		info("Mounted BPF filesystem at %s\n", bpfFsPath)
	} else {
		info("BPF filesystem already mounted at %s\n", bpfFsPath)
	}
	return nil
}

// loadPinnedCollection loads pinned programs and maps from the BPF filesystem
func loadPinnedCollection(bpfFsPath string) (*ebpf.Collection, error) {
	// Load pinned programs
	inboundProg, err := ebpf.LoadPinnedProgram(filepath.Join(bpfFsPath, "xdp_firewall_inbound"), nil)
	if err != nil {
		return nil, fmt.Errorf("loading pinned inbound program: %v", err)
	}
	outboundProg, err := ebpf.LoadPinnedProgram(filepath.Join(bpfFsPath, "tc_firewall_outbound"), nil)
	if err != nil {
		inboundProg.Close()
		return nil, fmt.Errorf("loading pinned outbound program: %v", err)
	}

	// Load pinned maps
	inboundRules, err := ebpf.LoadPinnedMap(filepath.Join(bpfFsPath, "inbound_rules"), nil)
	if err != nil {
		inboundProg.Close()
		outboundProg.Close()
		return nil, fmt.Errorf("loading pinned inbound_rules map: %v", err)
	}
	inboundPolicy, err := ebpf.LoadPinnedMap(filepath.Join(bpfFsPath, "inbound_default_policy"), nil)
	if err != nil {
		inboundProg.Close()
		outboundProg.Close()
		inboundRules.Close()
		return nil, fmt.Errorf("loading pinned inbound_default_policy map: %v", err)
	}
	outboundRules, err := ebpf.LoadPinnedMap(filepath.Join(bpfFsPath, "outbound_rules"), nil)
	if err != nil {
		inboundProg.Close()
		outboundProg.Close()
		inboundRules.Close()
		inboundPolicy.Close()
		return nil, fmt.Errorf("loading pinned outbound_rules map: %v", err)
	}
	outboundPolicy, err := ebpf.LoadPinnedMap(filepath.Join(bpfFsPath, "outbound_default_policy"), nil)
	if err != nil {
		inboundProg.Close()
		outboundProg.Close()
		inboundRules.Close()
		inboundPolicy.Close()
		outboundRules.Close()
		return nil, fmt.Errorf("loading pinned outbound_default_policy map: %v", err)
	}

	// Create collection
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"xdp_firewall_inbound":  inboundProg,
			"tc_firewall_outbound": outboundProg,
		},
		Maps: map[string]*ebpf.Map{
			"inbound_rules":          inboundRules,
			"inbound_default_policy": inboundPolicy,
			"outbound_rules":         outboundRules,
			"outbound_default_policy": outboundPolicy,
		},
	}
	return coll, nil
}

// attachPrograms attaches eBPF programs to the specified interface
func attachPrograms(ifaceName string, defaultDrop bool) (*ebpf.Collection, link.Link, link.Link, error) {
	// Remove MEMLOCK limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to remove memlock limit: %v", err)
	}

	// Ensure BPF filesystem is mounted
	if err := ensureBPFFilesystem(); err != nil {
		return nil, nil, nil, err
	}

	// Check if pinned objects exist
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName
	var xdpLink, tcLink link.Link
	if _, err := os.Stat(bpfFsPath); !os.IsNotExist(err) {
		// Try to load pinned collection
		coll, err := loadPinnedCollection(bpfFsPath)
		if err == nil {
			// Verify that links exist by checking attachment
			ifaceLink, err := netlink.LinkByName(ifaceName)
			if err != nil {
				coll.Close()
				return nil, nil, nil, fmt.Errorf("getting interface %s: %v", ifaceName, err)
			}
			if ifaceLink.Attrs().Xdp != nil && ifaceLink.Attrs().Xdp.Attached {
				info("XDP program already attached to %s\n", ifaceName)
			}
			filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
			if err == nil {
				for _, f := range filters {
					if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_firewall_outbound" {
						info("TC program already attached to %s\n", ifaceName)
						break
					}
				}
			}
			info("Using existing pinned eBPF objects at %s\n", bpfFsPath)
			return coll, nil, nil, nil
		}
		info("Existing pinned objects at %s are invalid, cleaning up\n", bpfFsPath)
		// Clean up invalid pinned objects
		for _, name := range []string{"xdp_firewall_inbound", "tc_firewall_outbound", "inbound_rules", "inbound_default_policy", "outbound_rules", "outbound_default_policy", "xdp_link", "tc_link"} {
			os.Remove(filepath.Join(bpfFsPath, name)) // Ignore errors
		}
		os.Remove(bpfFsPath) // Ignore errors
	}

	// Load eBPF specs
	inboundSpec, err := LoadInboundBPF()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading inbound eBPF spec: %v", err)
	}
	outboundSpec, err := LoadOutboundBPF()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading outbound eBPF spec: %v", err)
	}

	// Merge outbound maps and programs into inbound spec
	for name, m := range outboundSpec.Maps {
		inboundSpec.Maps[name] = m
	}
	for name, p := range outboundSpec.Programs {
		inboundSpec.Programs[name] = p
	}
	spec := inboundSpec

	// Check required maps and programs
	requiredMaps := []string{"inbound_rules", "inbound_default_policy", "outbound_rules", "outbound_default_policy"}
	for _, mapName := range requiredMaps {
		if spec.Maps[mapName] == nil {
			return nil, nil, nil, fmt.Errorf("required map '%s' not found in eBPF spec", mapName)
		}
	}
	requiredProgs := []string{"xdp_firewall_inbound", "tc_firewall_outbound"}
	for _, progName := range requiredProgs {
		if spec.Programs[progName] == nil {
			return nil, nil, nil, fmt.Errorf("required program '%s' not found in eBPF spec", progName)
		}
	}

	// Load eBPF collection
	collSpec := &ebpf.CollectionSpec{
		Maps:     spec.Maps,
		Programs: spec.Programs,
	}
	coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 2, // Enable verbose logging for debugging
		},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading eBPF collection: %v", err)
	}

	// Create pinning directory
	if err := os.MkdirAll(bpfFsPath, 0755); err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("creating BPF FS directory %s: %v", bpfFsPath, err)
	}

	// Pin maps
	for _, mapName := range requiredMaps {
		if err := coll.Maps[mapName].Pin(filepath.Join(bpfFsPath, mapName)); err != nil {
			coll.Close()
			return nil, nil, nil, fmt.Errorf("pinning map %s: %v", mapName, err)
		}
	}

	// Pin programs
	for _, progName := range requiredProgs {
		if err := coll.Programs[progName].Pin(filepath.Join(bpfFsPath, progName)); err != nil {
			coll.Close()
			return nil, nil, nil, fmt.Errorf("pinning program %s: %v", progName, err)
		}
	}
	success("Pinned eBPF programs and maps to %s\n", bpfFsPath)

	// Get interface
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("getting interface %s: %v", ifaceName, err)
	}

	// Attach XDP program
	inboundProg := coll.Programs["xdp_firewall_inbound"]
	if inboundProg == nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("inbound program not found in collection")
	}
	xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   inboundProg,
		Interface: ifaceLink.Attrs().Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("attaching XDP program to %s: %v", ifaceName, err)
	}
	if err := xdpLink.Pin(filepath.Join(bpfFsPath, "xdp_link")); err != nil {
		xdpLink.Close()
		coll.Close()
		return nil, nil, nil, fmt.Errorf("pinning XDP link: %v", err)
	}
	success("Successfully attached and pinned XDP program to %s\n", ifaceName)

	// Attach TC program
	outboundProg := coll.Programs["tc_firewall_outbound"]
	if outboundProg == nil {
		xdpLink.Close()
		coll.Close()
		return nil, nil, nil, fmt.Errorf("outbound program not found in collection")
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// if err := netlink.QdiscAdd(qdisc); err != nil && !strings.Contains(err.Error(), "file exists") {
	// 	xdpLink.Close()
	// 	coll.Close()
	// 	return nil, nil, nil, fmt.Errorf("adding qdisc to %s: %v", ifaceName, err)
	// }
	if err := netlink.QdiscAdd(qdisc); err != nil {
        // Qdisc might already exist, try to replace
        if err := netlink.QdiscReplace(qdisc); err != nil {
            return nil, nil, nil, fmt.Errorf("adding qdisc to %s: %v", ifaceName, err)
        }
    }

	/*
	tcLink, err = link.AttachTCX(link.TCXOptions{
		Program:   outboundProg,
		Interface: ifaceLink.Attrs().Index,
		Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		xdpLink.Close()
		netlink.QdiscDel(qdisc)
		coll.Close()
		return nil, nil, nil, fmt.Errorf("attaching TC program to %s: %v", ifaceName, err)
	}
	if err := tcLink.Pin(filepath.Join(bpfFsPath, "tc_link")); err != nil {
		tcLink.Close()
		xdpLink.Close()
		netlink.QdiscDel(qdisc)
		coll.Close()
		return nil, nil, nil, fmt.Errorf("pinning TC link: %v", err)
	}
	*/

	// Create TC filter with eBPF program
    filter := &netlink.BpfFilter{
        FilterAttrs: netlink.FilterAttrs{
            LinkIndex: ifaceLink.Attrs().Index,
            Parent:    netlink.HANDLE_MIN_INGRESS, // or netlink.HANDLE_MIN_EGRESS
            Handle:    netlink.MakeHandle(0, 1),
            Protocol:  unix.ETH_P_ALL,
            // Prio:      1,
        },
        Fd:           outboundProg.FD(),
        Name:         "tc_firewall_outbound",
        DirectAction: true,
    }

	if err := netlink.FilterAdd(filter); err != nil {
        return nil, nil, nil, fmt.Errorf("failed to add TC filter: %w", err)
    }

	success("Successfully attached and pinned TC program to %s\n", ifaceName)

	// Set default policies to DROP if specified
	if defaultDrop {
		if err := setDefaultPolicy(coll.Maps["inbound_default_policy"], "DROP", "inbound"); err != nil {
			tcLink.Close()
			xdpLink.Close()
			netlink.QdiscDel(qdisc)
			coll.Close()
			return nil, nil, nil, err
		}
		if err := setDefaultPolicy(coll.Maps["outbound_default_policy"], "DROP", "outbound"); err != nil {
			tcLink.Close()
			xdpLink.Close()
			netlink.QdiscDel(qdisc)
			coll.Close()
			return nil, nil, nil, err
		}
	}

	return coll, xdpLink, tcLink, nil
}

// detachPrograms detaches eBPF programs and removes pinned objects
func detachPrograms(ifaceName string) error {
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName

	// Unpin and close links
	for _, linkName := range []string{"xdp_link", "tc_link"} {
		lnk, err := link.LoadPinnedLink(filepath.Join(bpfFsPath, linkName), nil)
		if err == nil {
			if err := lnk.Unpin(); err != nil {
				return fmt.Errorf("unpinning %s: %v", linkName, err)
			}
			if err := lnk.Close(); err != nil {
				return fmt.Errorf("closing %s: %v", linkName, err)
			}
		}
	}

	// Detach TC qdisc
	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting interface %s: %v", ifaceName, err)
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil && !strings.Contains(err.Error(), "not found") {
		// return fmt.Errorf("deleting qdisc on %s: %v", ifaceName, err)
		
	}

	// Remove pinned programs and maps
	for _, name := range []string{"xdp_firewall_inbound", "tc_firewall_outbound", "inbound_rules", "inbound_default_policy", "outbound_rules", "outbound_default_policy"} {
		if err := os.Remove(filepath.Join(bpfFsPath, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing pinned object %s: %v", name, err)
		}
	}
	if err := os.Remove(bpfFsPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing BPF FS directory %s: %v", bpfFsPath, err)
	}

	success("Successfully detached eBPF programs and removed pinned objects from %s\n", ifaceName)
	return nil
}

// printRules prints the currently applied rules on the interface
func printRules(ifaceName string) error {
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
	coll, err := loadPinnedCollection(bpfFsPath)
	if err != nil {
		return fmt.Errorf("loading pinned eBPF objects from %s: %v", bpfFsPath, err)
	}
	defer coll.Close()

	// Print inbound rules
	inboundMap := coll.Maps["inbound_rules"]
	info("Inbound Rules:\n")
	var key RuleKey
	var value RuleValue
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

// auditRules compares YAML rules with currently applied rules
func auditRules(ifaceName, configPath string) error {
	config, err := loadConfig(configPath)
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
	coll, err := loadPinnedCollection(bpfFsPath)
	if err != nil {
		return fmt.Errorf("loading pinned eBPF objects from %s: %v", bpfFsPath, err)
	}
	defer coll.Close()

	// Compare inbound rules
	inboundMap := coll.Maps["inbound_rules"]
	var key RuleKey
	var value RuleValue
	appliedInbound := make(map[string]RuleValue)
	iter := inboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}
		ruleName := strings.TrimRight(string(value.RuleName[:]), "\x00")
		appliedInbound[ruleName] = value
	}

	configInbound := make(map[string]FirewallRule)
	for _, rule := range config.Inbound {
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
		configProto, _ := parseProtocol(configRule.Protocol)
		if configProto != applied.Protocol {
			errPrint(os.Stderr, "Inbound rule %s protocol mismatch: config=%s, applied=%d\n", ruleName, configRule.Protocol, applied.Protocol)
			differences++
		}
		configIP, configMask, _ := parseIPWithCIDR(configRule.IP)
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
			port, _ := parsePort(configRule.Port)
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
	appliedOutbound := make(map[string]RuleValue)
	iter = outboundMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Used == 0 || value.Enabled == 0 {
			continue
		}
		ruleName := strings.TrimRight(string(value.RuleName[:]), "\x00")
		appliedOutbound[ruleName] = value
	}

	configOutbound := make(map[string]FirewallRule)
	for _, rule := range config.Outbound {
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
		configProto, _ := parseProtocol(configRule.Protocol)
		if configProto != applied.Protocol {
			errPrint(os.Stderr, "Outbound rule %s protocol mismatch: config=%s, applied=%d\n", ruleName, configRule.Protocol, applied.Protocol)
			differences++
		}
		configIP, configMask, _ := parseIPWithCIDR(configRule.IP)
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
			port, _ := parsePort(configRule.Port)
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
		if strings.ToUpper(config.InboundPolicy) != policy {
			errPrint(os.Stderr, "Inbound default policy mismatch: config=%s, applied=%s\n", config.InboundPolicy, policy)
			differences++
		}
	}
	outboundDefaultMap := coll.Maps["outbound_default_policy"]
	if err := outboundDefaultMap.Lookup(&key, &defaultAction); err == nil {
		policy := "DROP"
		if defaultAction == 1 {
			policy = "ACCEPT"
		}
		if strings.ToUpper(config.OutboundPolicy) != policy {
			errPrint(os.Stderr, "Outbound default policy mismatch: config=%s, applied=%s\n", config.OutboundPolicy, policy)
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

func main() {
	// Define flags
	attachCmd := pflag.NewFlagSet("attach", pflag.ExitOnError)
	attachIface := attachCmd.String("interface", "", "Network interface to attach eBPF programs")
	attachNoDrop := attachCmd.Bool("no-drop", false, "Do not set default DROP policy")

	loadCmd := pflag.NewFlagSet("load", pflag.ExitOnError)
	loadIface := loadCmd.String("interface", "", "Network interface to attach eBPF programs")
	loadConfigFile := loadCmd.String("config", "", "Path to YAML configuration file")

	detachCmd := pflag.NewFlagSet("detach", pflag.ExitOnError)
	detachIface := detachCmd.String("interface", "", "Network interface to detach eBPF programs")

	auditCmd := pflag.NewFlagSet("audit", pflag.ExitOnError)
	auditIface := auditCmd.String("interface", "", "Network interface to audit")
	auditConfig := auditCmd.String("config", "", "Path to YAML configuration file")

	printCmd := pflag.NewFlagSet("print", pflag.ExitOnError)
	printIface := printCmd.String("interface", "", "Network interface to print rules")

	// Parse command
	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo ./firewall <command> [flags]")
		fmt.Println("Commands:")
		fmt.Println("  attach --interface <interface> [--no-drop]")
		fmt.Println("  load --interface <interface> --config <config.yaml>")
		fmt.Println("  detach --interface <interface>")
		fmt.Println("  audit --interface <interface> --config <config.yaml>")
		fmt.Println("  print --interface <interface>")
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "attach":
		if err := attachCmd.Parse(os.Args[2:]); err != nil {
			errPrint(os.Stderr, "Error parsing attach flags: %v\n", err)
			os.Exit(1)
		}
		if *attachIface == "" {
			errPrint(os.Stderr, "Error: --interface is required for attach command\n")
			attachCmd.Usage()
			os.Exit(1)
		}
		_, _, _, err := attachPrograms(*attachIface, !*attachNoDrop)
		if err != nil {
			errPrint(os.Stderr, "Error attaching programs: %v\n", err)
			os.Exit(1)
		}
		// Do not close coll, xdpLink, or tcLink to keep pinned objects alive
		info("eBPF programs attached and pinned to /sys/fs/bpf/slfw_%s; use 'detach' to remove\n", *attachIface)

	case "load":
		if err := loadCmd.Parse(os.Args[2:]); err != nil {
			errPrint(os.Stderr, "Error parsing load flags: %v\n", err)
			os.Exit(1)
		}
		if *loadIface == "" || *loadConfigFile == "" {
			errPrint(os.Stderr, "Error: --interface and --config are required for load command\n")
			loadCmd.Usage()
			os.Exit(1)
		}
		config, err := loadConfig(*loadConfigFile)
		if err != nil {
			errPrint(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
		// Check if pinned objects exist
		bpfFsPath := "/sys/fs/bpf/slfw_" + *loadIface
		var coll *ebpf.Collection
		if _, err := os.Stat(bpfFsPath); !os.IsNotExist(err) {
			coll, err = loadPinnedCollection(bpfFsPath)
			if err == nil {
				info("Using existing pinned eBPF objects at %s\n", bpfFsPath)
			} else {
				errPrint(os.Stderr, "Error loading pinned objects: %v; detaching and retrying\n", err)
				if err := detachPrograms(*loadIface); err != nil {
					errPrint(os.Stderr, "Error detaching programs: %v\n", err)
					os.Exit(1)
				}
				coll, _, _, err = attachPrograms(*loadIface, false)
				if err != nil {
					errPrint(os.Stderr, "Error attaching programs: %v\n", err)
					os.Exit(1)
				}
			}
		} else {
			coll, _, _, err = attachPrograms(*loadIface, false)
			if err != nil {
				errPrint(os.Stderr, "Error attaching programs: %v\n", err)
				os.Exit(1)
			}
		}
		defer coll.Close()
		// Apply rules
		if err := setDefaultPolicy(coll.Maps["inbound_default_policy"], config.InboundPolicy, "inbound"); err != nil {
			errPrint(os.Stderr, "Error setting inbound policy: %v\n", err)
			os.Exit(1)
		}
		if err := setDefaultPolicy(coll.Maps["outbound_default_policy"], config.OutboundPolicy, "outbound"); err != nil {
			errPrint(os.Stderr, "Error setting outbound policy: %v\n", err)
			os.Exit(1)
		}
		if err := processRules(config.Inbound, coll.Maps["inbound_rules"], "inbound", *loadIface); err != nil {
			errPrint(os.Stderr, "Error processing inbound rules: %v\n", err)
			os.Exit(1)
		}
		if err := processRules(config.Outbound, coll.Maps["outbound_rules"], "outbound", *loadIface); err != nil {
			errPrint(os.Stderr, "Error processing outbound rules: %v\n", err)
			os.Exit(1)
		}
		success("Firewall rules applied to interface %s\n", *loadIface)
		info("Firewall is running. Press Ctrl+C to stop.\n")
		select {}

	case "detach":
		if err := detachCmd.Parse(os.Args[2:]); err != nil {
			errPrint(os.Stderr, "Error parsing detach flags: %v\n", err)
			os.Exit(1)
		}
		if *detachIface == "" {
			errPrint(os.Stderr, "Error: --interface is required for detach command\n")
			detachCmd.Usage()
			os.Exit(1)
		}
		if err := detachPrograms(*detachIface); err != nil {
			errPrint(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "audit":
		if err := auditCmd.Parse(os.Args[2:]); err != nil {
			errPrint(os.Stderr, "Error parsing audit flags: %v\n", err)
			os.Exit(1)
		}
		if *auditIface == "" || *auditConfig == "" {
			errPrint(os.Stderr, "Error: --interface and --config are required for audit command\n")
			auditCmd.Usage()
			os.Exit(1)
		}
		if err := auditRules(*auditIface, *auditConfig); err != nil {
			errPrint(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "print":
		if err := printCmd.Parse(os.Args[2:]); err != nil {
			errPrint(os.Stderr, "Error parsing print flags: %v\n", err)
			os.Exit(1)
		}
		if *printIface == "" {
			errPrint(os.Stderr, "Error: --interface is required for print command\n")
			printCmd.Usage()
			os.Exit(1)
		}
		if err := printRules(*printIface); err != nil {
			errPrint(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		errPrint(os.Stderr, "Unknown command: %s\n", command)
		fmt.Println("Available commands: attach, load, detach, audit, print")
		os.Exit(1)
	}
}