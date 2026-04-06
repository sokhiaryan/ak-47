package engine

import "fmt"

var (
	ErrModuleNotFound = fmt.Errorf("module not found")
	ErrModuleExists   = fmt.Errorf("module already registered")
	ErrInvalidModule  = fmt.Errorf("invalid module")
	ErrInvalidOption  = fmt.Errorf("invalid option")
)

type Phase string

const (
	PhaseReconnaissance Phase = "reconnaissance"
	PhaseExploitation   Phase = "exploitation"
	PhaseDelivery       Phase = "delivery"
	PhaseExploitation2  Phase = "exploitation-post"
	PhaseInstallation   Phase = "installation"
	PhaseActions        Phase = "actions-on-objectives"
)

type Option func(*Options)

type Options struct {
	OutputFormat string
	Quiet        bool
	Timeout      int
	Workers      int
}

func WithOutputFormat(format string) Option {
	return func(o *Options) {
		o.OutputFormat = format
	}
}

func WithQuiet(quiet bool) Option {
	return func(o *Options) {
		o.Quiet = quiet
	}
}

func WithTimeout(timeout int) Option {
	return func(o *Options) {
		o.Timeout = timeout
	}
}

func WithWorkers(workers int) Option {
	return func(o *Options) {
		o.Workers = workers
	}
}

type ModuleMetadata struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Phase       Phase    `json:"phase"`
	MITRE       []string `json:"mitre,omitempty"`
	Author      string   `json:"author,omitempty"`
	Version     string   `json:"version,omitempty"`
}

type Result struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Errors    []string    `json:"errors,omitempty"`
	Module    string      `json:"module"`
	Target    string      `json:"target,omitempty"`
	Timestamp string      `json:"timestamp"`
	MITRE     []string    `json:"mitre,omitempty"`
}

type Module interface {
	Metadata() ModuleMetadata
	Configure(options map[string]string) error
	Execute(target string, opts Options) Result
}

type ConfigOption struct {
	Name        string
	Description string
	Default     string
	Required    bool
}

func (m ModuleMetadata) GetMITRE() string {
	if len(m.MITRE) == 0 {
		return ""
	}
	return m.MITRE[0]
}
