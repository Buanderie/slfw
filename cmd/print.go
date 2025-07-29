package cmd

import (
	"fmt"

	"firewall/rules"

	"github.com/spf13/cobra"
)

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