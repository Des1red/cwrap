package scan

import (
	"cwrap/internal/model"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Run(req model.Request) error {
	if err := validate(&req); err != nil {
		return err
	}

	base := strings.TrimRight(req.URL, "/")
	client := newClient()

	bf, err := buildBaseline(client, base)
	if err != nil {
		return err
	}
	bf.print()

	fmt.Printf("═══ Stage 1 — Directory Discovery ═══\n\n")
	r1 := stageOne(client, base, req.FilePath, bf)

	r2 := newScanResult()
	if len(r1.dirs) > 0 {
		fmt.Printf("\n═══ Stage 2 — Subdirectory Expansion (%d directories) ═══\n\n", len(r1.dirs))
		r2 = stageTwo(client, r1.dirs, req.FilePath, bf)
	}

	all := mergeResults(r1, r2)
	if len(all) > 0 {
		if err := saveResults(req.URL, all); err != nil {
			fmt.Printf("⚠  Could not save results: %v\n", err)
		}
	}
	return nil
}

func mergeResults(r1, r2 scanResult) []string {
	seen := make(map[string]bool)
	var out []string
	for url := range r1.hits {
		if !seen[url] {
			seen[url] = true
			out = append(out, url)
		}
	}
	for url := range r2.hits {
		if !seen[url] {
			seen[url] = true
			out = append(out, url)
		}
	}
	return out
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
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "/internal/scan/wordlists", "wordlist.txt")
}
