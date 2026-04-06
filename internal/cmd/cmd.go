package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sokhiaryan/ak-47/internal/engine"
	"github.com/sokhiaryan/ak-47/internal/output"
	"github.com/sokhiaryan/ak-47/internal/registry"
	"github.com/sokhiaryan/ak-47/modules/reconnaissance"
	"github.com/spf13/cobra"
)

var version = "0.1.0"
var outputFormat = "text"
var verbose = false

var globalRegistry = registry.New()

func init() {
	globalRegistry.Register(reconnaissance.NewPortScanner())
	globalRegistry.Register(reconnaissance.NewHTTPScanner())
	globalRegistry.Register(reconnaissance.NewDNSEnumerator())
	globalRegistry.Register(reconnaissance.NewSubnetScanner())
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(shellCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(infoCmd)
	runCmd.Flags().StringVar(&outputFormat, "output", "text", "Output format: text, json")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
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
			fmt.Println("==================")
			for _, mod := range modules {
				meta := mod.Metadata()
				fmt.Printf("  %-20s %s [%s]\n", meta.Name, meta.Description, meta.Phase)
			}
		case "search":
			if len(parts) < 2 {
				fmt.Println("Usage: search <query>")
				continue
			}
			results := globalRegistry.Search(parts[1])
			if len(results) == 0 {
				fmt.Printf("No modules found matching '%s'\n", parts[1])
			}
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
			fmt.Printf("\n=== %s ===\n", meta.Name)
			fmt.Printf("Description: %s\n", meta.Description)
			fmt.Printf("Phase:       %s\n", meta.Phase)
			fmt.Printf("Author:      %s\n", meta.Author)
			fmt.Printf("Version:     %s\n", meta.Version)
			fmt.Printf("MITRE:       %v\n", meta.MITRE)
			fmt.Println()
		case "options":
			if len(parts) < 2 {
				fmt.Println("Usage: options <module>")
				continue
			}
			_, err := globalRegistry.Get(parts[1])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			fmt.Printf("\n=== Options for %s ===\n", parts[1])
			fmt.Println("Available options:")
			fmt.Println("  ports     - Port range to scan")
			fmt.Println("  timeout   - Connection timeout (ms)")
			fmt.Println("  workers   - Concurrent workers")
			fmt.Println()
		case "set":
			if len(parts) < 3 {
				fmt.Println("Usage: set <key> <value>")
				fmt.Println("Note: Set options before running module")
				continue
			}
			fmt.Printf("Option %s set to %s (use before running module)\n", parts[1], parts[2])
		case "run", "fire":
			if len(parts) < 3 {
				fmt.Println("Usage: run <module> <target>")
				fmt.Println("Examples:")
				fmt.Println("  run port-scanner 192.168.1.1")
				fmt.Println("  run http-scanner example.com")
				fmt.Println("  run subnet-scanner 192.168.1.0/24")
				fmt.Println("  run dns-enum example.com")
				continue
			}
			mod, err := globalRegistry.Get(parts[1])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			result := mod.Execute(parts[2], engine.Options{Timeout: 30000, Workers: 50})
			formatter := output.GetFormatter(outputFormat)
			fmt.Print(formatter.Format(result))
		default:
			fmt.Printf("Unknown command: %s (type 'help' for available commands)\n", command)
		}
	}
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  list, ls              - List all modules")
	fmt.Println("  search <query>        - Search modules by name")
	fmt.Println("  info <module>         - Show module information")
	fmt.Println("  run <module> <t>     - Run module against target")
	fmt.Println("  options               - Show module options")
	fmt.Println("  set <key> <value>     - Set module option")
	fmt.Println("  help                  - Show this help")
	fmt.Println("  exit, quit            - Exit the shell")
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

		if verbose {
			log.Printf("[VERBOSE] Loading module: %s\n", moduleName)
			log.Printf("[VERBOSE] Target: %s\n", target)
		}

		result := mod.Execute(target, engine.Options{
			Timeout: 30000,
			Workers: 50,
		})

		if verbose {
			log.Printf("[VERBOSE] Module execution completed\n")
			log.Printf("[VERBOSE] Success: %v\n", result.Success)
		}

		formatter := output.GetFormatter(outputFormat)
		fmt.Print(formatter.Format(result))
	},
}

var infoCmd = &cobra.Command{
	Use:   "info <module>",
	Short: "Show detailed information about a module",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		moduleName := args[0]
		mod, err := globalRegistry.Get(moduleName)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		meta := mod.Metadata()
		fmt.Printf("\n=== Module Information: %s ===\n", meta.Name)
		fmt.Printf("Description: %s\n", meta.Description)
		fmt.Printf("Phase:       %s\n", meta.Phase)
		fmt.Printf("Author:      %s\n", meta.Author)
		fmt.Printf("Version:     %s\n", meta.Version)
		fmt.Printf("MITRE:       %v\n", meta.MITRE)
		fmt.Println()
	},
}
