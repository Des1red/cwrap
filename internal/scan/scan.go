package scan

import (
	"bufio"
	"crypto/tls"
	"cwrap/internal/model"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const workers = 20
const defautWordlist = "wordlists/directory-list-2.3-medium.txt"

func Run(req model.Request) error {
	if req.FilePath == "" {
		wl := defaultWordlist()
		if wl == "" {
			return fmt.Errorf("scan requires a wordlist — cwrap scan <url> /path/to/words.txt")
		}
		if _, err := os.Stat(wl); err != nil {
			return fmt.Errorf("no wordlist provided and default not found at %s", wl)
		}
		req.FilePath = wl
	}
	if req.URL == "" {
		return fmt.Errorf("scan requires a URL — cwrap scan <url> /path/to/words.txt")
	}

	f, err := os.Open(req.FilePath)
	if err != nil {
		return fmt.Errorf("wordlist: %w", err)
	}
	defer f.Close()

	base := strings.TrimRight(req.URL, "/")
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        workers,
			MaxIdleConnsPerHost: workers,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseline1, err := probe(client, base+"/cwrap-xqzjk-404check")
	if err != nil {
		return fmt.Errorf("baseline probe failed: %w", err)
	}
	baseline2, err := probe(client, base+"/cwrap-zvmpt-404check")
	if err != nil {
		return fmt.Errorf("baseline probe failed: %w", err)
	}

	soft404 := baseline1.status == 200
	trulyStatic := baseline1.hash == baseline2.hash

	if soft404 {
		if trulyStatic {
			fmt.Printf("⚠  Soft 404 detected — filtering by exact content match (baseline: %d bytes)\n\n", baseline1.size)
		} else {
			fmt.Printf("⚠  Soft 404 detected — server randomizes responses, filtering by size band (baseline: %d bytes)\n\n", baseline1.size)
		}
	}

	fmt.Printf("Scanning %s\n\n", base)

	words := make(chan string, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var hits []string // 200 URLs only, for saving

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range words {
				target := base + "/" + word
				result, err := probe(client, target)
				if err != nil {
					continue
				}

				if soft404 && result.status == 200 {
					if trulyStatic {
						if result.hash == baseline1.hash {
							continue
						}
					} else {
						if isSimilarSize(result.size, baseline1.size) {
							continue
						}
					}
				}

				line := formatResult(result.status, target, result.size)
				if line == "" {
					continue
				}

				mu.Lock()
				fmt.Println(line)
				if result.status != 404 && result.status != 500 &&
					result.status != 0 {
					hits = append(hits, target)
				}
				mu.Unlock()
			}
		}()
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		words <- word
	}
	close(words)
	wg.Wait()

	if len(hits) > 0 {
		if err := saveResults(req.URL, hits); err != nil {
			fmt.Printf("⚠  Could not save results: %v\n", err)
		}
	}

	return scanner.Err()
}

func isSimilarSize(a, b int64) bool {
	if b == 0 {
		return a == 0
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(b) < 0.05
}

func defaultWordlist() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// follow symlinks (go run creates a temp binary)
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "wordlists", "directory-list-2.3-medium.txt")
}
