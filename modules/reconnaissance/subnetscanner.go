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

type SubnetScanner struct {
	options map[string]string
	mu      sync.RWMutex
}

type SubnetResult struct {
	Host     string `json:"host"`
	Status   string `json:"status"`
	Hostname string `json:"hostname,omitempty"`
	Ports    []int  `json:"ports,omitempty"`
}

func NewSubnetScanner() *SubnetScanner {
	return &SubnetScanner{
		options: map[string]string{
			"subnet":      "24",
			"timeout":     "1000",
			"workers":     "50",
			"check-ports": "80,443,22,3389",
		},
	}
}

func (s *SubnetScanner) Metadata() engine.ModuleMetadata {
	return engine.ModuleMetadata{
		Name:        "subnet-scanner",
		Description: "CIDR range host discovery and port scanning",
		Phase:       engine.PhaseReconnaissance,
		MITRE:       []string{"T1040", "T1590"},
		Author:      "Sokhi Aryan",
		Version:     "1.0.0",
	}
}

func (s *SubnetScanner) Configure(options map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, value := range options {
		switch key {
		case "subnet", "timeout", "workers", "check-ports":
			s.options[key] = value
		default:
			return fmt.Errorf("%w: %s", engine.ErrInvalidOption, key)
		}
	}

	return nil
}

func (s *SubnetScanner) Execute(target string, opts engine.Options) engine.Result {
	s.mu.RLock()
	timeout, _ := strconv.Atoi(s.options["timeout"])
	workers, _ := strconv.Atoi(s.options["workers"])
	checkPorts := s.options["check-ports"]
	s.mu.RUnlock()

	if target == "" {
		return engine.Result{
			Success: false,
			Module:  "subnet-scanner",
			Message: "target subnet is required (e.g., 192.168.1.0/24)",
			Errors:  []string{"subnet not specified"},
		}
	}

	if timeout <= 0 {
		timeout = 1000
	}

	if workers <= 0 {
		workers = 50
	}

	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		if !strings.Contains(target, "/") {
			target = target + "/24"
			_, ipNet, err = net.ParseCIDR(target)
		}
		if err != nil {
			return engine.Result{
				Success: false,
				Module:  "subnet-scanner",
				Message: "invalid CIDR notation",
				Errors:  []string{err.Error()},
			}
		}
	}

	results := scanSubnet(ipNet, timeout, workers, checkPorts)

	return engine.Result{
		Success:   len(results) > 0,
		Module:    "subnet-scanner",
		Target:    target,
		Data:      results,
		Message:   fmt.Sprintf("scanned %s, found %d active hosts", target, len(results)),
		MITRE:     []string{"T1040", "T1590"},
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

func scanSubnet(ipNet *net.IPNet, timeout int, workers int, checkPorts string) []SubnetResult {
	results := []SubnetResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	ipList := []net.IP{}
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ipList = append(ipList, net.ParseIP(ip.String()))
		if len(ipList) >= 254 {
			break
		}
	}

	hostChan := make(chan net.IP, len(ipList))
	for _, ip := range ipList {
		hostChan <- ip
	}
	close(hostChan)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range hostChan {
				if isHostAlive(ip.String(), time.Duration(timeout)*time.Millisecond) {
					mu.Lock()
					result := SubnetResult{
						Host:   ip.String(),
						Status: "alive",
					}

					if checkPorts != "" {
						result.Ports = parsePortsList(checkPorts)
					}
					results = append(results, result)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	return results
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isHostAlive(host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", host), timeout)
	if err != nil {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", host), timeout)
		if err != nil {
			conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:22", host), timeout)
			if err != nil {
				return false
			}
		}
	}
	conn.Close()
	return true
}

func parsePortsList(portsStr string) []int {
	ports := []int{}
	for _, p := range strings.Split(portsStr, ",") {
		p = strings.TrimSpace(p)
		if port, err := strconv.Atoi(p); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

var _ engine.Module = (*SubnetScanner)(nil)
