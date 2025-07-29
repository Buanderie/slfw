package cmd

import (
	"fmt"

	"firewall/fwebpf"

	"github.com/spf13/cobra"
)

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