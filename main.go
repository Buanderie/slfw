package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" FirewallBPF ./bpf/inbound.c ./bpf/outbound.c

type Rule struct {
	Protocol        string `yaml:"protocol"`
	SourceIP        string `yaml:"source_ip"`
	DestinationIP   string `yaml:"destination_ip"`
	SourcePort      string `yaml:"source_port"`
	DestinationPort string `yaml:"destination_port"`
	ICMPType        int    `yaml:"icmp_type,omitempty"`
	Action          string `yaml:"action"`
	Description     string `yaml:"description"`
}

type DirectionConfig struct {
	DefaultPolicy string `yaml:"default_policy"`
	Rules         []Rule `yaml:"rules"`
}

type InterfaceConfig struct {
	Name     string          `yaml:"name"`
	Type     string          `yaml:"type"`
	Enabled  bool            `yaml:"enabled"`
	Inbound  DirectionConfig `yaml:"inbound"`
	Outbound DirectionConfig `yaml:"outbound"`
}

type FirewallConfig struct {
	Firewall struct {
		Interfaces []InterfaceConfig `yaml:"interfaces"`
	} `yaml:"firewall"`
}

// eBPF map structures
type RuleKey struct {
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	ICMPType  uint8
	SrcIPMask uint32
	DstIPMask uint32
}

type RuleValue struct {
	Action uint8
}

func parseIPWithCIDR(ipStr string) (uint32, uint32, error) {
	if ipStr == "any" {
		return 0, 0, nil
	}
	
	// Vérifier si c'est une IP simple sans CIDR
	if ip := net.ParseIP(ipStr); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return 0, 0, fmt.Errorf("only IPv4 is supported")
		}
		var ipInt uint32
		for i := 0; i < 4; i++ {
			ipInt |= uint32(ip4[i]) << (24 - 8*i)
		}
		return ipInt, 0xffffffff, nil // /32 par défaut
	}
	
	// Parser avec CIDR
	ip, ipNet, err := net.ParseCIDR(ipStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid IP/CIDR %s: %v", ipStr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, 0, fmt.Errorf("only IPv4 is supported")
	}
	mask, _ := ipNet.Mask.Size()
	var ipInt uint32
	for i := 0; i < 4; i++ {
		ipInt |= uint32(ip4[i]) << (24 - 8*i)
	}
	maskInt := uint32(0xffffffff) << (32 - mask)
	return ipInt, maskInt, nil
}

func parsePort(portStr string) (uint16, error) {
	if portStr == "any" {
		return 0, nil
	}
	var port uint16
	_, err := fmt.Sscanf(portStr, "%d", &port)
	return port, err
}

func loadConfig(filePath string) (*FirewallConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var config FirewallConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}
	return &config, nil
}

func main() {
	// Supprimer la limite MEMLOCK pour eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to remove memlock limit: %v\n", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo ./firewall <config.yaml>")
		os.Exit(1)
	}

	config, err := loadConfig(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Load eBPF programs - cette fonction doit être générée par bpf2go
	spec, err := LoadFirewallBPF()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading eBPF spec: %v\n", err)
		os.Exit(1)
	}

	// Debug: Afficher les maps disponibles
	fmt.Println("Available maps:")
	for name := range spec.Maps {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println("Available programs:")
	for name := range spec.Programs {
		fmt.Printf("  - %s\n", name)
	}

	// Vérifier les maps obligatoires (seulement inbound pour l'instant)
	requiredMaps := []string{"inbound_rules", "inbound_default_policy"}
	for _, mapName := range requiredMaps {
		if spec.Maps[mapName] == nil {
			fmt.Fprintf(os.Stderr, "Error: required map '%s' not found in eBPF spec\n", mapName)
			os.Exit(1)
		}
	}

	// Vérifier les programmes obligatoires (seulement inbound pour l'instant)
	requiredProgs := []string{"xdp_firewall_inbound"}
	for _, progName := range requiredProgs {
		if spec.Programs[progName] == nil {
			fmt.Fprintf(os.Stderr, "Error: required program '%s' not found in eBPF spec\n", progName)
			os.Exit(1)
		}
	}

	// Vérifier si les composants outbound existent
	hasOutboundSupport := spec.Maps["outbound_rules"] != nil && 
		spec.Maps["outbound_default_policy"] != nil && 
		spec.Programs["tc_firewall_outbound"] != nil

	if !hasOutboundSupport {
		fmt.Println("Warning: Outbound filtering not supported (missing maps/programs). Only inbound filtering will be active.")
	}

	// Charger toute la collection eBPF (obligatoire pour les références de maps)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading eBPF collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	// Récupérer les maps depuis la collection
	inboundMap := coll.Maps["inbound_rules"]
	inboundDefaultMap := coll.Maps["inbound_default_policy"]
	
	var outboundMap *ebpf.Map
	var outboundDefaultMap *ebpf.Map
	if hasOutboundSupport {
		outboundMap = coll.Maps["outbound_rules"]
		outboundDefaultMap = coll.Maps["outbound_default_policy"]
	}

	// Process each interface
	for _, iface := range config.Firewall.Interfaces {
		if !iface.Enabled {
			continue
		}

		// Récupérer les programmes depuis la collection
		inboundProg := coll.Programs["xdp_firewall_inbound"]
		if inboundProg == nil {
			fmt.Fprintf(os.Stderr, "Error: inbound program not found in collection\n")
			os.Exit(1)
		}

		var outboundProg *ebpf.Program
		if hasOutboundSupport {
			outboundProg = coll.Programs["tc_firewall_outbound"]
			if outboundProg == nil {
				fmt.Fprintf(os.Stderr, "Error: outbound program not found in collection\n")
				os.Exit(1)
			}
		}

		// Récupérer l'interface par son nom
		iface_link, err := netlink.LinkByName(iface.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting interface %s: %v\n", iface.Name, err)
			os.Exit(1)
		}

		// Attach inbound program (XDP)
		xdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   inboundProg,
			Interface: iface_link.Attrs().Index,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Cannot attach XDP program to %s: %v\n", iface.Name, err)
			fmt.Fprintf(os.Stderr, "Trying to use TC ingress as fallback...\n")
			
			// Fallback: utiliser TC ingress pour inbound
			qdisc := &netlink.GenericQdisc{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: iface_link.Attrs().Index,
					Handle:    netlink.MakeHandle(0xffff, 0),
					Parent:    netlink.HANDLE_CLSACT,
				},
				QdiscType: "clsact",
			}
			netlink.QdiscAdd(qdisc) // Ignorer l'erreur si existe déjà

			// Attacher en ingress (inbound)
			filter := &netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: iface_link.Attrs().Index,
					Parent:    netlink.HANDLE_MIN_INGRESS,
					Handle:    1,
					Protocol:  unix.ETH_P_ALL,
				},
				Fd:           inboundProg.FD(),
				Name:         "tc_firewall_inbound",
				DirectAction: true,
			}
			
			if err := netlink.FilterAdd(filter); err != nil {
				fmt.Fprintf(os.Stderr, "Error attaching TC ingress program to %s: %v\n", iface.Name, err)
				continue
			}
			fmt.Printf("Successfully attached TC ingress filter to %s\n", iface.Name)
		} else {
			defer xdpLink.Close()
			fmt.Printf("Successfully attached XDP program to %s\n", iface.Name)
		}

		// Attacher le programme TC seulement si disponible
		if hasOutboundSupport && outboundProg != nil {
			// Pour TC, utiliser netlink directement car cilium/ebpf ne supporte pas toujours TC
			// Créer un qdisc clsact si nécessaire
			qdisc := &netlink.GenericQdisc{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: iface_link.Attrs().Index,
					Handle:    netlink.MakeHandle(0xffff, 0),
					Parent:    netlink.HANDLE_CLSACT,
				},
				QdiscType: "clsact",
			}
			// Ignorer l'erreur si le qdisc existe déjà
			netlink.QdiscAdd(qdisc)

			// Attacher le programme TC en utilisant netlink
			filter := &netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: iface_link.Attrs().Index,
					Parent:    netlink.HANDLE_MIN_EGRESS,
					Handle:    1,
					Protocol:  unix.ETH_P_ALL,
				},
				Fd:           outboundProg.FD(),
				Name:         "tc_firewall_outbound",
				DirectAction: true,
			}
			
			if err := netlink.FilterAdd(filter); err != nil {
				fmt.Fprintf(os.Stderr, "Error attaching TC program to %s: %v\n", iface.Name, err)
			}
		} else {
			fmt.Printf("Skipping outbound filtering for interface %s (not supported)\n", iface.Name)
		}

		// Set default policies
		var defaultKey uint32 = 0 // Single key for default policy
		inboundDefaultAction := uint8(0) // DROP
		if iface.Inbound.DefaultPolicy == "ACCEPT" {
			inboundDefaultAction = 1
		}
		if err := inboundDefaultMap.Update(unsafe.Pointer(&defaultKey), unsafe.Pointer(&inboundDefaultAction), ebpf.UpdateAny); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting inbound default policy for %s: %v\n", iface.Name, err)
		}

		if hasOutboundSupport && outboundDefaultMap != nil {
			outboundDefaultAction := uint8(0) // DROP
			if iface.Outbound.DefaultPolicy == "ACCEPT" {
				outboundDefaultAction = 1
			}
			if err := outboundDefaultMap.Update(unsafe.Pointer(&defaultKey), unsafe.Pointer(&outboundDefaultAction), ebpf.UpdateAny); err != nil {
				fmt.Fprintf(os.Stderr, "Error setting outbound default policy for %s: %v\n", iface.Name, err)
			}
		}

		// Populate inbound rules
		fmt.Printf("Loading %d inbound rules for interface %s...\n", len(iface.Inbound.Rules), iface.Name)
		for i, rule := range iface.Inbound.Rules {
			fmt.Printf("Processing rule %d: %s %s:%s -> %s:%s (%s)\n", 
				i+1, rule.Protocol, rule.SourceIP, rule.SourcePort, 
				rule.DestinationIP, rule.DestinationPort, rule.Action)
			
			key := RuleKey{}
			value := RuleValue{}

			// Map protocol strings to numbers
			protocolMap := map[string]uint8{
				"tcp":  6,
				"udp":  17,
				"icmp": 1,
				"all":  0,
			}
			if proto, exists := protocolMap[rule.Protocol]; exists {
				key.Protocol = proto
				fmt.Printf("  Protocol: %s -> %d\n", rule.Protocol, proto)
			} else {
				fmt.Fprintf(os.Stderr, "Unknown protocol: %s\n", rule.Protocol)
				continue
			}

			key.SrcIP, key.SrcIPMask, err = parseIPWithCIDR(rule.SourceIP)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing source IP %s: %v\n", rule.SourceIP, err)
				continue
			}
			fmt.Printf("  Source IP: %s -> %d (mask: %d)\n", rule.SourceIP, key.SrcIP, key.SrcIPMask)
			
			key.DstIP, key.DstIPMask, err = parseIPWithCIDR(rule.DestinationIP)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing destination IP %s: %v\n", rule.DestinationIP, err)
				continue
			}
			fmt.Printf("  Dest IP: %s -> %d (mask: %d)\n", rule.DestinationIP, key.DstIP, key.DstIPMask)
			
			key.SrcPort, err = parsePort(rule.SourcePort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing source port %s: %v\n", rule.SourcePort, err)
				continue
			}
			fmt.Printf("  Source port: %s -> %d\n", rule.SourcePort, key.SrcPort)
			
			key.DstPort, err = parsePort(rule.DestinationPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing destination port %s: %v\n", rule.DestinationPort, err)
				continue
			}
			fmt.Printf("  Dest port: %s -> %d\n", rule.DestinationPort, key.DstPort)
			
			key.ICMPType = uint8(rule.ICMPType)
			
			// Map action strings to numbers
			if rule.Action == "ACCEPT" {
				value.Action = 1
				fmt.Printf("  Action: ACCEPT -> 1\n")
			} else if rule.Action == "DROP" {
				value.Action = 0
				fmt.Printf("  Action: DROP -> 0\n")
			} else {
				fmt.Fprintf(os.Stderr, "Unknown action: %s\n", rule.Action)
				continue
			}

			fmt.Printf("  Final key: SrcIP=%d, DstIP=%d, SrcPort=%d, DstPort=%d, Proto=%d\n",
				key.SrcIP, key.DstIP, key.SrcPort, key.DstPort, key.Protocol)

			if err := inboundMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny); err != nil {
				fmt.Fprintf(os.Stderr, "Error updating inbound map: %v\n", err)
			} else {
				fmt.Printf("  ✓ Rule successfully added to eBPF map\n")
			}
			fmt.Println()
		}

		// Populate outbound rules seulement si supporté
		if hasOutboundSupport && outboundMap != nil {
			for _, rule := range iface.Outbound.Rules {
				key := RuleKey{}
				value := RuleValue{}

				// Map protocol strings to numbers
				protocolMap := map[string]uint8{
					"tcp":  6,
					"udp":  17,
					"icmp": 1,
					"all":  0,
				}
				if proto, exists := protocolMap[rule.Protocol]; exists {
					key.Protocol = proto
				} else {
					fmt.Fprintf(os.Stderr, "Unknown protocol: %s\n", rule.Protocol)
					continue
				}

				key.SrcIP, key.SrcIPMask, err = parseIPWithCIDR(rule.SourceIP)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing source IP %s: %v\n", rule.SourceIP, err)
					continue
				}
				key.DstIP, key.DstIPMask, err = parseIPWithCIDR(rule.DestinationIP)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing destination IP %s: %v\n", rule.DestinationIP, err)
					continue
				}
				key.SrcPort, err = parsePort(rule.SourcePort)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing source port %s: %v\n", rule.SourcePort, err)
					continue
				}
				key.DstPort, err = parsePort(rule.DestinationPort)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing destination port %s: %v\n", rule.DestinationPort, err)
					continue
				}
				key.ICMPType = uint8(rule.ICMPType)
				
				// Map action strings to numbers
				if rule.Action == "ACCEPT" {
					value.Action = 1
				} else if rule.Action == "DROP" {
					value.Action = 0
				} else {
					fmt.Fprintf(os.Stderr, "Unknown action: %s\n", rule.Action)
					continue
				}

				if err := outboundMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny); err != nil {
					fmt.Fprintf(os.Stderr, "Error updating outbound map: %v\n", err)
				}
			}
		} else if len(iface.Outbound.Rules) > 0 {
			fmt.Printf("Warning: Skipping %d outbound rules for interface %s (outbound not supported)\n", 
				len(iface.Outbound.Rules), iface.Name)
		}

		fmt.Printf("Firewall rules applied to interface %s\n", iface.Name)
	}

	fmt.Println("Firewall is running. Press Ctrl+C to stop.")
	select {}
}