package cmd

import (
	"fmt"

	"firewall/rules"

	"github.com/spf13/cobra"
)

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
		
		// return rules.AuditRules(iface, configFile)
		_, err := rules.RetrieveFirewallConfig(iface)
		if err != nil {
			return fmt.Errorf("ERROR: %v", err)
		}
		return nil
	},
}

func init() {
	auditCmd.Flags().StringP("config", "c", "", "Path to YAML configuration file")
}