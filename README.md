# AK-47: Modular Offensive Security Framework (Go)

[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/sokhiaryan/ak-47)](https://github.com/sokhiaryan/ak-47/stargazers)

AK-47 is a high-performance, modular penetration testing framework written in Go, designed to model real-world adversarial behavior through structured attack methodologies. The framework is architected around the Cyber Kill Chain and the MITRE ATT&CK framework, enabling a systematic and extensible approach to offensive security operations.

## Features

- **Modular Architecture**: Plugin-based system for easy extension
- **Cyber Kill Chain Aligned**: Modules mapped to attack phases
- **MITRE ATT&CK Integration**: Each module tagged with relevant tactics/techniques
- **Concurrent Execution**: High-performance scanning using goroutines
- **Interactive Shell**: Professional CLI with search/load/run workflow
- **Structured Output**: JSON and text formats for pipelines
- **Verbose Mode**: Detailed execution logging with `-v` flag

## Installation

```bash
git clone https://github.com/sokhiaryan/ak-47.git
cd ak-47
go build -o ak-47 ./cmd/cli
```

## Usage

### CLI Commands

```bash
# List available modules
./ak-47 list

# Search modules
./ak-47 search port

# Get module info
./ak-47 info port-scanner

# Run a module
./ak-47 run port-scanner 192.168.1.1

# Run with JSON output
./ak-47 run port-scanner 192.168.1.1 --output json

# Run with verbose output
./ak-47 run port-scanner 192.168.1.1 -v

# Interactive shell
./ak-47 shell
```

### Interactive Shell

```
ak-47> list
ak-47> search http
ak-47> info port-scanner
ak-47> options port-scanner
ak-47> run port-scanner 192.168.1.1
ak-47> exit
```

## Architecture

```
ak-47/
├── cmd/cli/           # CLI entry point
├── internal/
│   ├── cmd/           # CLI commands and shell
│   ├── engine/        # Core module interface
│   ├── registry/      # Module registry
│   └── output/        # Formatters (JSON/Text)
├── modules/
│   └── reconnaissance/ # Scanning modules
└── data/mitre/        # MITRE ATT&CK mappings
```

## Available Modules

| Module | Description | MITRE |
|--------|-------------|-------|
| port-scanner | High-performance concurrent TCP port scanner | T1040 |
| http-scanner | HTTP/HTTPS service enumeration and fingerprinting | T1040, T1083 |
| dns-enum | DNS enumeration and subdomain discovery | T1040, T1589 |
| subnet-scanner | CIDR range host discovery and port scanning | T1040, T1590 |

## Development

```bash
# Build
make build

# Test
make test

# Run
make run
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized scanning of systems you do not own is illegal and unethical.
