package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

const workers = 20

type scanMode int

const (
	scanAllPaths scanMode = iota
	scanSingleSegmentsOnly
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

func shouldSkipWord(word string, mode scanMode) bool {
	if word == "" || strings.HasPrefix(word, "#") {
		return true
	}

	// never allow traversal-style payloads in directory scanner
	if strings.Contains(word, "..") {
		return true
	}

	if mode == scanSingleSegmentsOnly {
		if strings.Contains(word, "/") ||
			strings.Contains(word, "?") ||
			strings.Contains(word, ".") {
			return true
		}
	}

	return false
}

func scanBase(client *http.Client, base, wordlist string, bf baseline, mode scanMode) scanResult {
	result := newScanResult()

	f, err := os.Open(wordlist)
	if err != nil {
		fmt.Printf("⚠  Could not open wordlist: %v\n", err)
		return result
	}
	defer f.Close()

	var wordList []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if shouldSkipWord(word, mode) {
			continue
		}
		wordList = append(wordList, strings.TrimLeft(word, "/"))
	}
	total := len(wordList)

	words := make(chan string, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var checked int64

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range words {
				isExpandable := !strings.Contains(word, "/") &&
					!strings.Contains(word, "?") &&
					!strings.Contains(word, ".")
				target := base + "/" + word
				res, err := probe(client, target)

				mu.Lock()
				checked++
				if err != nil {
					fmt.Printf("\r  progress: %d/%d", checked, total)
					mu.Unlock()
					continue
				}

				if bf.soft404 && res.status == 200 {
					if bf.trulyStatic {
						if res.hash == bf.b1.hash {
							fmt.Printf("\r  progress: %d/%d", checked, total)
							mu.Unlock()
							continue
						}
					} else {
						if isSimilarSize(res.size, bf.b1.size) {
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

				// print hit then redraw progress on same line
				fmt.Printf("\r%s\n", line)
				fmt.Printf("  progress: %d/%d", checked, total)

				if res.status != 404 && res.status != 500 && res.status != 0 {
					result.hits[target] = res.status
					if res.status == 200 && isExpandable {
						result.dirs[target] = true
					}
				}
				mu.Unlock()
			}
		}()
	}

	// feed from the already-loaded slice — not the file again
	for _, word := range wordList {
		words <- word
	}
	close(words)
	wg.Wait()

	fmt.Printf("\r\033[K") // \r go to start, \033[K clear to end of line
	return result
}
