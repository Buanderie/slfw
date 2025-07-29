package cmd

import (
	"fmt"
	"os"

	"firewall/config"
	"firewall/fwebpf"
	"firewall/rules"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cilium/ebpf"
)

// Initialize colored output
var (
	info     = color.New(color.FgBlue).PrintfFunc()
	success  = color.New(color.FgGreen).PrintfFunc()
	errPrint = color.New(color.FgRed).FprintfFunc()
)

var rootCmd = &cobra.Command{
	Use:   "firewall",
	Short: "eBPF-based firewall management tool",
	Long: `A comprehensive eBPF firewall that uses XDP for inbound traffic filtering
and TC (Traffic Control) for outbound traffic filtering.

This tool allows you to attach, configure, and manage firewall rules
on network interfaces using high-performance eBPF programs.`,
}

var attachCmd = &cobra.Command{
	Use:   "attach",
	Short: "Attach eBPF programs to a network interface",
	Long: `Attach XDP and TC eBPF programs to the specified network interface.
This creates the necessary eBPF programs and maps, and pins them to the BPF filesystem
for persistence across program restarts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		iface, _ := cmd.Flags().GetString("interface")
		noDrop, _ := cmd.Flags().GetBool("no-drop")
		
		if iface == "" {
			return fmt.Errorf("--interface is required")
		}
		
		_, _, _, err := fwebpf.AttachPrograms(iface, !noDrop)
		if err != nil {
			return fmt.Errorf("attaching programs: %v", err)
		}
		
		info("eBPF programs attached and pinned to /sys/fs/bpf/slfw_%s; use 'detach' to remove\n", iface)
		return nil
	},
}

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
		if err := rules.SetDefaultPolicy(coll.Maps["inbound_default_policy"], cfg.InboundPolicy, "inbound"); err != nil {
			return fmt.Errorf("setting inbound policy: %v", err)
		}
		if err := rules.SetDefaultPolicy(coll.Maps["outbound_default_policy"], cfg.OutboundPolicy, "outbound"); err != nil {
			return fmt.Errorf("setting outbound policy: %v", err)
		}
		if err := rules.ProcessRules(cfg.Inbound, coll.Maps["inbound_rules"], "inbound", iface); err != nil {
			return fmt.Errorf("processing inbound rules: %v", err)
		}
		if err := rules.ProcessRules(cfg.Outbound, coll.Maps["outbound_rules"], "outbound", iface); err != nil {
			return fmt.Errorf("processing outbound rules: %v", err)
		}
		
		success("Firewall rules applied to interface %s\n", iface)
		info("Firewall is running. Press Ctrl+C to stop.\n")
		select {}
	},
}

var detachCmd = &cobra.Command{
	Use:   "detach",
	Short: "Detach eBPF programs from a network interface",
	Long: `Detach XDP and TC eBPF programs from the specified network interface.
This removes all pinned objects from the BPF filesystem and cleans up
any qdisc configurations that were created.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		iface, _ := cmd.Flags().GetString("interface")
		
		if iface == "" {
			return fmt.Errorf("--interface is required")
		}
		
		return fwebpf.DetachPrograms(iface)
	},
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit currently applied rules against configuration",
	Long: `Compare the currently applied eBPF rules with the rules defined
in the configuration file. This command will report any differences
between the expected configuration and the actual applied rules.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		iface, _ := cmd.Flags().GetString("interface")
		configFile, _ := cmd.Flags().GetString("config")
		
		if iface == "" || configFile == "" {
			return fmt.Errorf("--interface and --config are required")
		}
		
		return rules.AuditRules(iface, configFile)
	},
}

var printCmd = &cobra.Command{
	Use:   "print",
	Short: "Print currently applied firewall rules",
	Long: `Display all currently applied firewall rules for the specified
network interface, including inbound rules, outbound rules, and
default policies.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		iface, _ := cmd.Flags().GetString("interface")
		
		if iface == "" {
			return fmt.Errorf("--interface is required")
		}
		
		return rules.PrintRules(iface)
	},
}

func init() {
	// Add persistent flags for interface
	rootCmd.PersistentFlags().StringP("interface", "i", "", "Network interface name (required for most commands)")
	
	// Attach command flags
	attachCmd.Flags().Bool("no-drop", false, "Do not set default DROP policy when attaching")
	
	// Load command flags
	loadCmd.Flags().StringP("config", "c", "", "Path to YAML configuration file")
	
	// Audit command flags
	auditCmd.Flags().StringP("config", "c", "", "Path to YAML configuration file")
	
	// Add commands to root
	rootCmd.AddCommand(attachCmd)
	rootCmd.AddCommand(loadCmd)
	rootCmd.AddCommand(detachCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(printCmd)
}

func Execute() error {
	return rootCmd.Execute()
}