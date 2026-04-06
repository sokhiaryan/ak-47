package reconnaissance

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sokhiaryan/ak-47/internal/engine"
)

type PortScanner struct {
	options map[string]string
	mu      sync.RWMutex
}

type PortResult struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service,omitempty"`
}

func NewPortScanner() *PortScanner {
	return &PortScanner{
		options: map[string]string{
			"ports":     "1-1000",
			"timeout":   "1000",
			"workers":   "50",
			"top-ports": "100",
		},
	}
}

func (s *PortScanner) Metadata() engine.ModuleMetadata {
	return engine.ModuleMetadata{
		Name:        "port-scanner",
		Description: "High-performance concurrent TCP port scanner",
		Phase:       engine.PhaseReconnaissance,
		MITRE:       []string{"T1040"},
		Author:      "Sokhi Aryan",
		Version:     "1.0.0",
	}
}

func (s *PortScanner) Configure(options map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, value := range options {
		switch key {
		case "ports", "timeout", "workers", "top-ports":
			s.options[key] = value
		default:
			return fmt.Errorf("%w: %s", engine.ErrInvalidOption, key)
		}
	}

	return nil
}

func (s *PortScanner) Execute(target string, opts engine.Options) engine.Result {
	s.mu.RLock()
	ports := s.options["ports"]
	timeout, _ := strconv.Atoi(s.options["timeout"])
	workers, _ := strconv.Atoi(s.options["workers"])
	s.mu.RUnlock()

	if target == "" {
		return engine.Result{
			Success: false,
			Module:  "port-scanner",
			Message: "target is required",
			Errors:  []string{"target not specified"},
		}
	}

	if timeout <= 0 {
		timeout = 1000
	}

	if workers <= 0 {
		workers = 50
	}

	portList := parsePortSpec(ports)

	results := make([]PortResult, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	portChan := make(chan int, len(portList))
	for _, p := range portList {
		portChan <- p
	}
	close(portChan)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				status := scanPort(target, port, time.Duration(timeout)*time.Millisecond)
				mu.Lock()
				results = append(results, PortResult{
					Port:   port,
					Status: status,
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	openPorts := filterOpenPorts(results)

	return engine.Result{
		Success:   len(openPorts) > 0,
		Module:    "port-scanner",
		Target:    target,
		Data:      openPorts,
		Message:   fmt.Sprintf("scanned %d ports, found %d open", len(portList), len(openPorts)),
		MITRE:     []string{"T1040"},
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

func parsePortSpec(spec string) []int {
	spec = strings.TrimSpace(spec)

	if spec == "top-100" {
		return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017}
	}

	if strings.Contains(spec, "-") {
		parts := strings.Split(spec, "-")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			ports := make([]int, 0, end-start+1)
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			return ports
		}
	}

	if strings.Contains(spec, ",") {
		parts := strings.Split(spec, ",")
		ports := make([]int, 0, len(parts))
		for _, p := range parts {
			if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ports = append(ports, port)
			}
		}
		return ports
	}

	if port, err := strconv.Atoi(spec); err == nil {
		return []int{port}
	}

	return []int{}
}

func scanPort(host string, port int, timeout time.Duration) string {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "closed"
	}
	conn.Close()
	return "open"
}

func filterOpenPorts(results []PortResult) []PortResult {
	open := make([]PortResult, 0)
	for _, r := range results {
		if r.Status == "open" {
			open = append(open, r)
		}
	}
	return open
}

var _ engine.Module = (*PortScanner)(nil)
