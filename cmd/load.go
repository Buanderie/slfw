package cmd

import (
	"fmt"
	"os"

	"firewall/config"
	"firewall/fwebpf"
	"firewall/rules"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
)

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load firewall rules from configuration file",
	Long: `Load and apply firewall rules from a YAML configuration file.
If eBPF programs are not already attached to the interface, they will be
attached automatically. The configuration file defines inbound and outbound
rules along with default policies.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		iface, _ := cmd.Flags().GetString("interface")
		configFile, _ := cmd.Flags().GetString("config")
		
		if iface == "" || configFile == "" {
			return fmt.Errorf("--interface and --config are required")
		}
		
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("loading config: %v", err)
		}
		
		// Check if pinned objects exist
		bpfFsPath := "/sys/fs/bpf/slfw_" + iface
		var coll *ebpf.Collection
		if _, err := os.Stat(bpfFsPath); !os.IsNotExist(err) {
			coll, err = fwebpf.LoadPinnedCollection(bpfFsPath)
			if err == nil {
				info("Using existing pinned eBPF objects at %s\n", bpfFsPath)
			} else {
				errPrint(os.Stderr, "Error loading pinned objects: %v; detaching and retrying\n", err)
				if err := fwebpf.DetachPrograms(iface); err != nil {
					return fmt.Errorf("detaching programs: %v", err)
				}
				coll, _, _, err = fwebpf.AttachPrograms(iface, false)
				if err != nil {
					return fmt.Errorf("attaching programs: %v", err)
				}
			}
		} else {
			coll, _, _, err = fwebpf.AttachPrograms(iface, false)
			if err != nil {
				return fmt.Errorf("attaching programs: %v", err)
			}
		}
		defer coll.Close()
		
		// Apply rules
		if err := fwebpf.SetDefaultPolicy(coll.Maps["inbound_default_policy"], cfg.InboundPolicy, "inbound"); err != nil {
			return fmt.Errorf("setting inbound policy: %v", err)
		}
		if err := fwebpf.SetDefaultPolicy(coll.Maps["outbound_default_policy"], cfg.OutboundPolicy, "outbound"); err != nil {
			return fmt.Errorf("setting outbound policy: %v", err)
		}
		if err := rules.ProcessRules(cfg.Inbound, coll.Maps["inbound_rules"], iface); err != nil {
			return fmt.Errorf("processing inbound rules: %v", err)
		}
		if err := rules.ProcessRules(cfg.Outbound, coll.Maps["outbound_rules"], iface); err != nil {
			return fmt.Errorf("processing outbound rules: %v", err)
		}
		
		success("Firewall rules applied to interface %s\n", iface)

		return nil
	},
}

func init() {
	loadCmd.Flags().StringP("config", "c", "", "Path to YAML configuration file")
}