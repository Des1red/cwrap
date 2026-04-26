package scan

import (
	"fmt"
	"net/http"
	"sync"
)

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
