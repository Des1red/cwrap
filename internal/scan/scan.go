package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

type scanResult struct {
	hits map[string]int  // url -> status — everything we like
	dirs map[string]bool // url -> true — only 200s for stage 2
}

func newScanResult() scanResult {
	return scanResult{
		hits: make(map[string]int),
		dirs: make(map[string]bool),
	}
}

func stageOne(client *http.Client, base, wordlist string, bf baseline) scanResult {
	return scanBase(client, base, wordlist, bf)
}

func stageTwo(client *http.Client, dirs map[string]bool, wordlist string, bf baseline) scanResult {
	merged := newScanResult()
	var mu sync.Mutex
	var wg sync.WaitGroup

	for dir := range dirs {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			fmt.Printf("  expanding %s\n", d)
			r := scanBase(client, d, wordlist, bf)
			mu.Lock()
			for url, status := range r.hits {
				merged.hits[url] = status
			}
			for url := range r.dirs {
				merged.dirs[url] = true
			}
			mu.Unlock()
		}(dir)
	}
	wg.Wait()
	return merged
}

func scanBase(client *http.Client, base, wordlist string, bf baseline) scanResult {
	result := newScanResult()

	f, err := os.Open(wordlist)
	if err != nil {
		fmt.Printf("⚠  Could not open wordlist: %v\n", err)
		return result
	}
	defer f.Close()

	words := make(chan string, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range words {
				target := base + "/" + word
				res, err := probe(client, target)
				if err != nil {
					continue
				}

				if bf.soft404 && res.status == 200 {
					if bf.trulyStatic {
						if res.hash == bf.b1.hash {
							continue
						}
					} else {
						if isSimilarSize(res.size, bf.b1.size) {
							continue
						}
					}
				}

				line := formatResult(res.status, target, res.size)
				if line == "" {
					continue
				}

				mu.Lock()
				fmt.Println(line)
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

	return result
}
