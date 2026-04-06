package reconnaissance

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sokhiaryan/ak-47/internal/engine"
)

type HTTPScanner struct {
	options map[string]string
	mu      sync.RWMutex
}

type HTTPResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Title  string `json:"title,omitempty"`
	Server string `json:"server,omitempty"`
	Tech   string `json:"tech,omitempty"`
}

func NewHTTPScanner() *HTTPScanner {
	return &HTTPScanner{
		options: map[string]string{
			"ports":      "80,443,8080,8443",
			"timeout":    "5000",
			"workers":    "10",
			"follow":     "true",
			"user-agent": "AK-47/1.0",
		},
	}
}

func (s *HTTPScanner) Metadata() engine.ModuleMetadata {
	return engine.ModuleMetadata{
		Name:        "http-scanner",
		Description: "HTTP/HTTPS service enumeration and fingerprinting",
		Phase:       engine.PhaseReconnaissance,
		MITRE:       []string{"T1040", "T1083"},
		Author:      "Sokhi Aryan",
		Version:     "1.0.0",
	}
}

func (s *HTTPScanner) Configure(options map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, value := range options {
		switch key {
		case "ports", "timeout", "workers", "follow", "user-agent":
			s.options[key] = value
		default:
			return fmt.Errorf("%w: %s", engine.ErrInvalidOption, key)
		}
	}

	return nil
}

func (s *HTTPScanner) Execute(target string, opts engine.Options) engine.Result {
	s.mu.RLock()
	ports := s.options["ports"]
	timeout, _ := strconv.Atoi(s.options["timeout"])
	workers, _ := strconv.Atoi(s.options["workers"])
	userAgent := s.options["user-agent"]
	s.mu.RUnlock()

	if target == "" {
		return engine.Result{
			Success: false,
			Module:  "http-scanner",
			Message: "target is required",
			Errors:  []string{"target not specified"},
		}
	}

	if timeout <= 0 {
		timeout = 5000
	}

	if workers <= 0 {
		workers = 10
	}

	portList := parsePortSpec(ports)
	if len(portList) == 0 {
		portList = []int{80, 443, 8080, 8443}
	}

	results := make([]HTTPResult, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	targetHost := target
	if !strings.Contains(targetHost, ":") && !strings.HasPrefix(targetHost, "http") {
		targetHost = fmt.Sprintf("http://%s", targetHost)
	}

	portChan := make(chan int, len(portList))
	for _, p := range portList {
		portChan <- p
	}
	close(portChan)

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("User-Agent", userAgent)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				result := scanHTTP(targetHost, port, client, req)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	activeSites := filterActiveHTTP(results)

	return engine.Result{
		Success:   len(activeSites) > 0,
		Module:    "http-scanner",
		Target:    target,
		Data:      activeSites,
		Message:   fmt.Sprintf("scanned %d ports, found %d active HTTP services", len(portList), len(activeSites)),
		MITRE:     []string{"T1040", "T1083"},
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

func scanHTTP(target string, port int, client *http.Client, req *http.Request) HTTPResult {
	var result HTTPResult

	protocols := []string{"http", "https"}
	for _, proto := range protocols {
		url := fmt.Sprintf("%s://%s:%d", proto, strings.TrimPrefix(target, "http://"), port)
		req.URL, _ = req.URL.Parse(url)

		resp, err := client.Do(req)
		if err == nil {
			result = HTTPResult{
				URL:    url,
				Status: resp.StatusCode,
			}
			if server := resp.Header.Get("Server"); server != "" {
				result.Server = server
			}
			if title := resp.Header.Get("Title"); title != "" {
				result.Title = title
			}
			resp.Body.Close()
			break
		}

		if _, ok := err.(*net.OpError); !ok {
			break
		}
	}

	return result
}

func filterActiveHTTP(results []HTTPResult) []HTTPResult {
	active := make([]HTTPResult, 0)
	for _, r := range results {
		if r.Status > 0 {
			active = append(active, r)
		}
	}
	return active
}

var _ engine.Module = (*HTTPScanner)(nil)
