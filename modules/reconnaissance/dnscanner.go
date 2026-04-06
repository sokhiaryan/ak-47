package reconnaissance

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sokhiaryan/ak-47/internal/engine"
)

type DNSEnumerator struct {
	options map[string]string
	mu      sync.RWMutex
}

type DNSResult struct {
	Record   string `json:"record"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Priority int    `json:"priority,omitempty"`
}

var commonDNSRecords = []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"}

var dnsWordlist = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "dns",
	"test", "ns2", "mail2", "new", "mysql", "www2", "admin", "tools", "git",
	"ns", "mail1", "code", "m", "shop", "support", "cdn", "blog", "vpn",
	"ns3", "mail3", "www3", "forum", "news", "ww", "gateway", "s1", "uAT",
	"host", "server", "ns4", "www1", "backup", "mx1", "linux", "windows",
	"loan", "dating", "download", "demo", "xxx", "bc", "bok", "shop", "my",
}

func NewDNSEnumerator() *DNSEnumerator {
	return &DNSEnumerator{
		options: map[string]string{
			"domain":   "",
			"wordlist": "common",
			"timeout":  "2000",
			"workers":  "10",
		},
	}
}

func (e *DNSEnumerator) Metadata() engine.ModuleMetadata {
	return engine.ModuleMetadata{
		Name:        "dns-enum",
		Description: "DNS enumeration and subdomain discovery",
		Phase:       engine.PhaseReconnaissance,
		MITRE:       []string{"T1040", "T1589"},
		Author:      "Sokhi Aryan",
		Version:     "1.0.0",
	}
}

func (e *DNSEnumerator) Configure(options map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for key, value := range options {
		switch key {
		case "domain", "wordlist", "timeout", "workers":
			e.options[key] = value
		default:
			return fmt.Errorf("%w: %s", engine.ErrInvalidOption, key)
		}
	}

	return nil
}

func (e *DNSEnumerator) Execute(target string, opts engine.Options) engine.Result {
	e.mu.RLock()
	wordlist := e.options["wordlist"]
	timeout, _ := strconv.Atoi(e.options["timeout"])
	workers, _ := strconv.Atoi(e.options["workers"])
	e.mu.RUnlock()

	if target == "" {
		return engine.Result{
			Success: false,
			Module:  "dns-enum",
			Message: "target domain is required",
			Errors:  []string{"domain not specified"},
		}
	}

	if timeout <= 0 {
		timeout = 2000
	}

	if workers <= 0 {
		workers = 10
	}

	domain := strings.TrimPrefix(target, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	results := performDNSEnum(domain, wordlist, timeout, workers)

	return engine.Result{
		Success:   len(results) > 0,
		Module:    "dns-enum",
		Target:    domain,
		Data:      results,
		Message:   fmt.Sprintf("enumerated %s, found %d DNS records", domain, len(results)),
		MITRE:     []string{"T1040", "T1589"},
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

func performDNSEnum(domain, wordlist string, timeout, workers int) []DNSResult {
	results := []DNSResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Duration(timeout) * time.Millisecond}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	var subdomains []string
	if wordlist == "common" {
		subdomains = dnsWordlist
	} else {
		subdomains = dnsWordlist
	}

	subChan := make(chan string, len(subdomains))
	for _, s := range subdomains {
		subChan <- s
	}
	close(subChan)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range subChan {
				host := fmt.Sprintf("%s.%s", sub, domain)

				ips, err := resolver.LookupHost(context.Background(), host)
				if err == nil && len(ips) > 0 {
					for _, ip := range ips {
						mu.Lock()
						results = append(results, DNSResult{
							Record: host,
							Value:  ip,
							Type:   "A",
						})
						mu.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()

	performZoneTransfer(domain, &results)

	return results
}

func performZoneTransfer(domain string, results *[]DNSResult) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil || len(nsRecords) == 0 {
		return
	}

	for _, ns := range nsRecords {
		server := strings.TrimSuffix(ns.Host, ".")

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:53", server), 5*time.Second)
		if err != nil {
			continue
		}
		defer conn.Close()
	}
}

var _ engine.Module = (*DNSEnumerator)(nil)
