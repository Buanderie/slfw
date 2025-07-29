package cmd

import (
	"fmt"

	"firewall/fwebpf"

	"github.com/spf13/cobra"
)

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

func init() {
	attachCmd.Flags().Bool("no-drop", false, "Do not set default DROP policy when attaching")
}