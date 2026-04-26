package scan

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// stageThree enumerates subdomains of the apex host extracted from base.
// It builds its own wildcard baseline before scanning.
func stageThree(client *http.Client, base, wordlist string) scanResult {
	result := newScanResult()

	u, err := url.Parse(base)
	if err != nil {
		fmt.Printf("⚠  Stage 3 skipped — could not parse base URL: %v\n", err)
		return result
	}

	scheme := u.Scheme
	host := u.Hostname() // strips port
	port := u.Port()

	apex := apexHost(host)

	sbf, err := buildSubdomainBaseline(client, scheme, apex, port)
	if err != nil {
		fmt.Printf("⚠  Stage 3 skipped — subdomain baseline failed: %v\n", err)
		return result
	}
	sbf.printSubdomain()

	return scanSubdomains(client, scheme, apex, port, wordlist, sbf)
}

// scanSubdomains probes word.<apex> for each word in the wordlist.
func scanSubdomains(client *http.Client, scheme, apex, port, wordlist string, sbf baseline) scanResult {
	result := newScanResult()

	f, err := os.Open(wordlist)
	if err != nil {
		fmt.Printf("⚠  Could not open subdomain wordlist: %v\n", err)
		return result
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		words = append(words, w)
	}

	total := len(words)
	wordCh := make(chan string, workers)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		checked int64
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordCh {
				target := buildSubdomainURL(scheme, word, apex, port)

				res, err := probe(client, target)

				mu.Lock()
				checked++

				if err != nil {
					fmt.Printf("\r  progress: %d/%d", checked, total)
					mu.Unlock()
					continue
				}

				// wildcard filter — same logic as directory baseline
				if sbf.soft404 && res.status == 200 {
					if sbf.trulyStatic {
						if res.hash == sbf.b1.hash {
							fmt.Printf("\r  progress: %d/%d", checked, total)
							mu.Unlock()
							continue
						}
					} else {
						if isSimilarSize(res.size, sbf.b1.size) {
							fmt.Printf("\r  progress: %d/%d", checked, total)
							mu.Unlock()
							continue
						}
					}
				}

				line := formatResult(res.status, target, res.size)
				if line == "" {
					fmt.Printf("\r  progress: %d/%d", checked, total)
					mu.Unlock()
					continue
				}

				fmt.Printf("\r%s\n", line)
				fmt.Printf("  progress: %d/%d", checked, total)

				if res.status != 404 && res.status != 500 && res.status != 0 {
					result.hits[target] = res.status
					if res.status == 200 {
						result.dirs[target] = true
					}
				}

				mu.Unlock()
			}
		}()
	}

	for _, w := range words {
		wordCh <- w
	}
	close(wordCh)
	wg.Wait()

	fmt.Printf("\r\033[K")
	return result
}

// buildSubdomainURL constructs scheme://word.apex[:port]
func buildSubdomainURL(scheme, word, apex, port string) string {
	host := word + "." + apex
	if port != "" {
		host = host + ":" + port
	}
	return scheme + "://" + host
}

// apexHost strips leading subdomain components to get the registrable domain.
// e.g. "api.staging.example.com" → "example.com"
// Falls back to the full host for IPs or single-label names.
func apexHost(host string) string {
	parts := strings.Split(host, ".")
	// bare hostname or IP — return as-is
	if len(parts) <= 2 {
		return host
	}
	// handles common ccTLD two-parters: co.uk, com.au, co.jp etc.
	twoPartTLDs := map[string]bool{
		"co.uk": true, "co.jp": true, "co.nz": true, "co.za": true,
		"com.au": true, "com.br": true, "com.mx": true, "com.ar": true,
		"net.au": true, "org.uk": true, "me.uk": true, "gov.uk": true,
		"ac.uk": true, "ltd.uk": true, "plc.uk": true,
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if twoPartTLDs[last2] && len(parts) >= 3 {
		// keep SLD + ccTLD pair → last 3 parts
		return strings.Join(parts[len(parts)-3:], ".")
	}
	// default: last 2 parts = apex
	return last2
}

// defaultSubdomainWordlist returns the path to the bundled subdomain wordlist,
// resolved relative to the cwrap executable — same pattern as defaultWordlist().
func defaultSubdomainWordlist() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "./", "small-subdomain-list-20k.txt")
}

// validateSubdomainFile resolves which subdomain wordlist to use.
// Prefers req.SubdomainFile, falls back to the bundled default.
// Returns "" if no wordlist is available (stage 3 will be skipped gracefully).
func resolveSubdomainFile(provided string) string {
	if provided != "" {
		return provided
	}
	wl := defaultSubdomainWordlist()
	if wl == "" {
		return ""
	}
	if _, err := os.Stat(wl); err != nil {
		return ""
	}
	return wl
}

func subdomainSkipReason(base, subdomainFile string) string {
	// explicit flag provided — always attempt regardless of host type
	if subdomainFile != "" {
		return ""
	}

	// no explicit flag — check whether the host is worth scanning
	u, err := url.Parse(base)
	if err != nil {
		return "could not parse target URL"
	}
	host := u.Hostname()

	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return "target is localhost — use --domain to force subdomain scan"
	}
	if net.ParseIP(host) != nil {
		return "target is an IP address — use --domain to force subdomain scan"
	}

	// no flag and no bundled wordlist
	if resolveSubdomainFile("") == "" {
		return "no subdomain wordlist found — use --domain /path/to/subdomains.txt"
	}

	return ""
}
