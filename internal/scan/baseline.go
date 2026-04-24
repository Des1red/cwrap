package scan

import (
	"cwrap/internal/model"
	"fmt"
	"net/http"
	"os"
)

type baseline struct {
	soft404     bool
	trulyStatic bool
	b1          probeResult
}

func (b baseline) print() {
	if !b.soft404 {
		return
	}
	if b.trulyStatic {
		fmt.Printf("⚠  Soft 404 detected — filtering by exact content match (baseline: %d bytes)\n\n", b.b1.size)
	} else {
		fmt.Printf("⚠  Soft 404 detected — server randomizes responses, filtering by size band (baseline: %d bytes)\n\n", b.b1.size)
	}
}

func buildBaseline(client *http.Client, base string) (baseline, error) {
	b1, err := probe(client, base+"/cwrap-xqzjk-404check")
	if err != nil {
		return baseline{}, fmt.Errorf("baseline probe failed: %w", err)
	}
	b2, err := probe(client, base+"/cwrap-zvmpt-404check")
	if err != nil {
		return baseline{}, fmt.Errorf("baseline probe failed: %w", err)
	}
	return baseline{
		soft404:     b1.status == 200,
		trulyStatic: b1.hash == b2.hash,
		b1:          b1,
	}, nil
}

func validate(req *model.Request) error {
	if req.URL == "" {
		return fmt.Errorf("scan requires a URL — cwrap scan <url> /path/to/words.txt")
	}
	if req.FilePath != "" {
		return nil
	}
	wl := defaultWordlist()
	if wl == "" {
		return fmt.Errorf("scan requires a wordlist — cwrap scan <url> /path/to/words.txt")
	}
	if _, err := os.Stat(wl); err != nil {
		return fmt.Errorf("no wordlist provided and default not found at %s", wl)
	}
	req.FilePath = wl
	return nil
}
