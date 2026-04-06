package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "ak-47",
	Short: "AK-47 - Modular Offensive Security Framework",
	Long: `AK-47 is a high-performance, modular penetration testing 
framework written in Go, designed to model real-world 
adversarial behavior through structured attack methodologies.

The framework is architected around the Cyber Kill Chain and 
the MITRE ATT&CK framework.`,
	Version: version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of AK-47",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("AK-47 v%s\n", version)
	},
}
