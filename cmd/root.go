package cmd

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
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

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("interface", "i", "", "Network interface name (required for most commands)")
	
	// Add commands to root
	rootCmd.AddCommand(attachCmd)
	rootCmd.AddCommand(loadCmd)
	rootCmd.AddCommand(detachCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(printCmd)
}