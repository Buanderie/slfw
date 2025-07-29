package fwebpf

import (
	"fmt"
	"os"
	"path/filepath"

	"strings"
	
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// LoadPinnedCollection loads pinned programs and maps from the BPF filesystem
func LoadPinnedCollection(bpfFsPath string) (*ebpf.Collection, error) {
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

// AttachPrograms attaches eBPF programs to the specified interface
func AttachPrograms(ifaceName string, defaultDrop bool) (*ebpf.Collection, link.Link, link.Link, error) {
	// Remove MEMLOCK limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to remove memlock limit: %v", err)
	}

	// Ensure BPF filesystem is mounted
	if err := EnsureBPFFilesystem(); err != nil {
		return nil, nil, nil, err
	}

	// Check if pinned objects exist
	bpfFsPath := "/sys/fs/bpf/slfw_" + ifaceName
	var xdpLink, tcLink link.Link
	if _, err := os.Stat(bpfFsPath); !os.IsNotExist(err) {
		// Try to load pinned collection
		coll, err := LoadPinnedCollection(bpfFsPath)
		if err == nil {
			// Verify that links exist by checking attachment
			ifaceLink, err := netlink.LinkByName(ifaceName)
			if err != nil {
				coll.Close()
				return nil, nil, nil, fmt.Errorf("getting interface %s: %v", ifaceName, err)
			}
			if ifaceLink.Attrs().Xdp != nil && ifaceLink.Attrs().Xdp.Attached {
				fmt.Printf("XDP program already attached to %s\n", ifaceName)
			}
			filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
			if err == nil {
				for _, f := range filters {
					if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_firewall_outbound" {
						fmt.Printf("TC program already attached to %s\n", ifaceName)
						break
					}
				}
			}
			fmt.Printf("Using existing pinned eBPF objects at %s\n", bpfFsPath)
			return coll, nil, nil, nil
		}
		fmt.Printf("Existing pinned objects at %s are invalid, cleaning up\n", bpfFsPath)
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
			LogLevel: 3, // Enable verbose logging for debugging
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
	fmt.Printf("Pinned eBPF programs and maps to %s\n", bpfFsPath)

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
		progFD := inboundProg.FD()
		if progFD < 0 {
			return nil, nil, nil, fmt.Errorf("invalid inbound BPF program FD")
		}
		if err := netlink.LinkSetXdpFd(ifaceLink, progFD); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to attach XDP program to %s: %v", ifaceName, err)
		}
		coll.Close()
		return nil, nil, nil, fmt.Errorf("attaching XDP program to %s: %v", ifaceName, err)
	}
	if err := xdpLink.Pin(filepath.Join(bpfFsPath, "xdp_link")); err != nil {
		xdpLink.Close()
		coll.Close()
		return nil, nil, nil, fmt.Errorf("pinning XDP link: %v", err)
	}
	fmt.Printf("Successfully attached and pinned XDP program to %s\n", ifaceName)

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

	if err := netlink.QdiscAdd(qdisc); err != nil {
		// Qdisc might already exist, try to replace
		if err := netlink.QdiscReplace(qdisc); err != nil {
			return nil, nil, nil, fmt.Errorf("adding qdisc to %s: %v", ifaceName, err)
		}
	}

	// Create TC filter with eBPF program
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           outboundProg.FD(),
		Name:         "tc_firewall_outbound",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to add TC filter: %v", err)
	}

	fmt.Printf("Successfully attached and pinned TC program to %s\n", ifaceName)

	return coll, xdpLink, tcLink, nil
}

// DetachPrograms detaches eBPF programs and removes pinned objects
func DetachPrograms(ifaceName string) error {
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
		// Ignore "not found" errors
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

	fmt.Printf("Successfully detached eBPF programs and removed pinned objects from %s\n", ifaceName)
	return nil
}