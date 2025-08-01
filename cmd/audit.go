package cmd

import (
	"fmt"
	"strings"

	"firewall/config"
	"firewall/rules"
	"github.com/fatih/color"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// AuditResult holds the result of the rule comparison, including differences.
type AuditResult struct {
	Match        bool     // True if rules match exactly
	MissingRules [][]byte // Rules in config but not enforced
	ExtraRules   [][]byte // Rules enforced but not in config
}

// compareBinaryMultiSets compares two multisets of binary rules, returning an AuditResult.
// Counts duplicates and is order-invariant.
func compareBinaryMultiSets(configRules, enforcedRules [][]byte) AuditResult {
	// Count config rules
	configMap := make(map[string]int)
	for _, rule := range configRules {
		configMap[string(rule)]++
	}

	// Count enforced rules
	enforcedMap := make(map[string]int)
	for _, rule := range enforcedRules {
		enforcedMap[string(rule)]++
	}

	// Find differences
	var missing, extra [][]byte
	for key, configCount := range configMap {
		enforcedCount, exists := enforcedMap[key]
		if !exists {
			// Rule in config but not enforced
			for i := 0; i < configCount; i++ {
				missing = append(missing, []byte(key))
			}
		} else if enforcedCount < configCount {
			// Fewer instances in enforced than config
			for i := 0; i < configCount-enforcedCount; i++ {
				missing = append(missing, []byte(key))
			}
		} else if enforcedCount > configCount {
			// More instances in enforced than config
			for i := 0; i < enforcedCount-configCount; i++ {
				extra = append(extra, []byte(key))
			}
		}
	}

	// Check for rules in enforced but not in config
	for key, enforcedCount := range enforcedMap {
		if _, exists := configMap[key]; !exists {
			// Rule in enforced but not in config
			for i := 0; i < enforcedCount; i++ {
				extra = append(extra, []byte(key))
			}
		}
	}

	return AuditResult{
		Match:        len(missing) == 0 && len(extra) == 0,
		MissingRules: missing,
		ExtraRules:   extra,
	}
}

func PrintRuleSignature(rule []byte) (string, error) {
	var retStr string
	rv, err := rules.ParseRuleBinarySignature(rule, 18)
	if err != nil {
		return retStr, fmt.Errorf("Error parsing rule signature: %v\n", err)
	}
	if err != nil {
		return retStr, fmt.Errorf("Error: %v\n", err)
	} else {
		// fmt.Printf("rv  - %x\n", rv)
		convRule, err := rules.ConvertBinaryRuleToFirewallRule(rv)
		if err != nil {
			return retStr, fmt.Errorf("Error converting binary rule to firewall rule: %v", err)
		}
		// fmt.Printf("convRule  - %s\n", convRule.Protocol)
		retBytes, err := yaml.Marshal(&convRule)
		retStr = string(retBytes)
		if err != nil {
			return retStr, fmt.Errorf("error marshaling to YAML: %v", err)
		}
	}
	return retStr, nil
}

func AuditRuleMap(iface string, mapName string, configMap []config.FirewallRule) error {

	// Retrieve enforced rules
	fwInboundRules, err := rules.RetrieveFirewallBinaryRules(iface, mapName)
	if err != nil {
		return fmt.Errorf("retrieving enforced rules: %v", err)
	}

	// Convert enforced rules to binary signatures
	var enforcedBinaryRules [][]byte
	for _, rule := range fwInboundRules {
		brule, err := rules.GetRuleBinarySignature(rule)
		if err != nil {
			return fmt.Errorf("converting enforced rule to binary: %v", err)
		}
		enforcedBinaryRules = append(enforcedBinaryRules, brule)
	}

	// Convert config rules to binary signatures
	var configBinaryRules [][]byte
	for _, rule := range configMap {
		bvalue, err := rules.FirewallRuleToEBPF(rule)
		if err != nil {
			return fmt.Errorf("converting config rule %v to eBPF: %v", rule, err)
		}
		brule, err := rules.GetRuleBinarySignature(bvalue)
		if err != nil {
			return fmt.Errorf("converting config rule to binary: %v", err)
		}
		configBinaryRules = append(configBinaryRules, brule)
	}

	// Compare rules
	result := compareBinaryMultiSets(configBinaryRules, enforcedBinaryRules)

	// Print audit report
	if result.Match {
		fmt.Println(color.GreenString("Audit passed: Enforced rules match configuration."))
		return nil
	}

	fmt.Println(color.RedString("Audit failed: Differences found between configuration and enforced rules."))
	if len(result.MissingRules) > 0 {
		fmt.Println("Missing rules (in config but not enforced):")
		for _, rule := range result.MissingRules {
			fmt.Printf("  - %x\n", rule)
			yamlStr, _ := PrintRuleSignature(rule)
			fmt.Printf("%s\n", color.RedString("%s", yamlStr))
		}
	}
	if len(result.ExtraRules) > 0 {
		fmt.Println("Extra rules (enforced but not in config):")
		for _, rule := range result.ExtraRules {
			fmt.Printf("  - %x\n", rule)
			yamlStr, _ := PrintRuleSignature(rule)
			fmt.Printf("%s\n", color.GreenString("%s", yamlStr))
		}
	}
	return nil
}

func AuditDefaultPolicy(iface string, mapName string, expectedPolicy string) error {
	// Retrieve enforced default policy
	enforcedPolicy, err := rules.GetDefaultPolicy(iface, mapName)
	if err != nil {
		return fmt.Errorf("retrieving enforced default policy: %v", err)
	}

	// Compare policies
	if enforcedPolicy == strings.ToUpper(expectedPolicy) {
		fmt.Println(color.GreenString("Default policy matches configuration."))
		return nil
	}

	fmt.Printf(color.RedString("Default policy mismatch: expected '%s', got '%s'.\n"), expectedPolicy, strings.ToUpper(enforcedPolicy))
	return fmt.Errorf("default policy mismatch")
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit currently applied rules against configuration",
	Long: `Compare the currently applied eBPF rules with the rules defined
in the configuration file. This command will report any differences
between the expected configuration and the actual applied rules.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		iface, err := cmd.Flags().GetString("interface")
		if err != nil || iface == "" {
			return fmt.Errorf("--interface is required")
		}
		configFile, err := cmd.Flags().GetString("config")
		if err != nil || configFile == "" {
			return fmt.Errorf("--config is required")
		}

		// Load configuration
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("loading config: %v", err)
		}

		var errs []string

		bold := color.New(color.Bold)

		bold.Println("Audit result for INBOUND rules:")
		if err := AuditRuleMap(iface, "inbound_rules", cfg.Inbound); err != nil {
    		errs = append(errs, err.Error())
		}
		bold.Println("Audit result for INBOUND default policy:")
		if err := AuditDefaultPolicy(iface, "inbound_default_policy", cfg.InboundPolicy); err != nil {
    		errs = append(errs, err.Error())
		}

		bold.Println("Audit result for OUTBOUND rules:")
		if err := AuditRuleMap(iface, "outbound_rules", cfg.Outbound); err != nil {
    		errs = append(errs, err.Error())
		}
		bold.Println("Audit result for OUTBOUND default policy:")
		if err := AuditDefaultPolicy(iface, "outbound_default_policy", cfg.OutboundPolicy); err != nil {
    		errs = append(errs, err.Error())
		}

		if len(errs) > 0 {
    		return fmt.Errorf("audit failed: %s", strings.Join(errs, "; "))
		}

		return nil
	},
}

func init() {
	auditCmd.Flags().StringP("config", "c", "", "Path to YAML configuration file")
	auditCmd.Flags().StringP("interface", "i", "", "Network interface to audit")
	auditCmd.MarkFlagRequired("config")
	auditCmd.MarkFlagRequired("interface")
}