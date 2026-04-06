package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/sokhiaryan/ak-47/internal/engine"
	"github.com/sokhiaryan/ak-47/internal/registry"
	"github.com/sokhiaryan/ak-47/modules/reconnaissance"
	"github.com/spf13/cobra"
)

var version = "0.1.0"

var globalRegistry = registry.New()

func init() {
	globalRegistry.Register(reconnaissance.NewPortScanner())
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(shellCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(runCmd)
}

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

func startShell() {
	fmt.Println("AK-47 Interactive Shell")
	fmt.Println("=========================")
	fmt.Println("Type 'help' for available commands, 'exit' to quit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("ak-47> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := strings.ToLower(parts[0])

		switch command {
		case "exit", "quit":
			fmt.Println("Goodbye!")
			return
		case "help":
			printHelp()
		case "list", "ls":
			modules := globalRegistry.List()
			fmt.Println("Available modules:")
			for _, mod := range modules {
				meta := mod.Metadata()
				fmt.Printf("  %s - %s [%s]\n", meta.Name, meta.Description, meta.Phase)
			}
		case "search":
			if len(parts) < 2 {
				fmt.Println("Usage: search <query>")
				continue
			}
			results := globalRegistry.Search(parts[1])
			for _, mod := range results {
				meta := mod.Metadata()
				fmt.Printf("  %s\n", meta.Name)
			}
		case "info":
			if len(parts) < 2 {
				fmt.Println("Usage: info <module>")
				continue
			}
			mod, err := globalRegistry.Get(parts[1])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			meta := mod.Metadata()
			fmt.Printf("Name: %s\n", meta.Name)
			fmt.Printf("Description: %s\n", meta.Description)
			fmt.Printf("Phase: %s\n", meta.Phase)
			fmt.Printf("MITRE: %v\n", meta.MITRE)
		case "run", "fire":
			if len(parts) < 3 {
				fmt.Println("Usage: run <module> <target>")
				continue
			}
			mod, err := globalRegistry.Get(parts[1])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			result := mod.Execute(parts[2], engine.Options{Timeout: 30000, Workers: 50})
			if result.Success {
				fmt.Printf("[+] %s\n", result.Message)
			} else {
				fmt.Printf("[-] %s\n", result.Message)
			}
		default:
			fmt.Printf("Unknown command: %s\n", command)
		}
	}
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  list, ls          - List all modules")
	fmt.Println("  search <query>    - Search modules by name")
	fmt.Println("  info <module>     - Show module information")
	fmt.Println("  run <module> <t> - Run module against target")
	fmt.Println("  help              - Show this help")
	fmt.Println("  exit, quit        - Exit the shell")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of AK-47",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("AK-47 v%s\n", version)
	},
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Enter interactive shell mode",
	Run: func(cmd *cobra.Command, args []string) {
		startShell()
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available modules",
	Run: func(cmd *cobra.Command, args []string) {
		modules := globalRegistry.List()
		fmt.Println("Available modules:")
		fmt.Println("==================")
		for _, mod := range modules {
			meta := mod.Metadata()
			fmt.Printf("  %s - %s [%s]\n", meta.Name, meta.Description, meta.Phase)
		}
	},
}

var searchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search for modules",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		query := args[0]
		results := globalRegistry.Search(query)
		if len(results) == 0 {
			fmt.Printf("No modules found matching '%s'\n", query)
			return
		}
		fmt.Printf("Found %d module(s):\n", len(results))
		for _, mod := range results {
			meta := mod.Metadata()
			fmt.Printf("  %s - %s\n", meta.Name, meta.Description)
		}
	},
}

var runCmd = &cobra.Command{
	Use:   "run <module> <target>",
	Short: "Run a module against a target",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		moduleName := args[0]
		target := args[1]

		mod, err := globalRegistry.Get(moduleName)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		result := mod.Execute(target, engine.Options{
			Timeout: 30000,
			Workers: 50,
		})

		if result.Success {
			fmt.Printf("[+] %s\n", result.Message)
		} else {
			fmt.Printf("[-] %s\n", result.Message)
		}
	},
}
