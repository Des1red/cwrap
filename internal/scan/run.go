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
	client := newClient(req)

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

	// ── Stage 3 — Subdomain Enumeration ──────────────────────────────────────
	fmt.Printf("\n═══ Stage 3 — Subdomain Enumeration ═══\n\n")
	r3 := newScanResult()

	switch reason := subdomainSkipReason(base, req.SubdomainFile); reason {
	case "":
		subFile := resolveSubdomainFile(req.SubdomainFile)
		r3 = stageThree(client, base, subFile)
	default:
		fmt.Printf("  skipped — %s\n", reason)
	}

	all := mergeResults(r1, r2, r3)
	if len(all) > 0 {
		if err := saveResults(req.URL, all); err != nil {
			fmt.Printf("⚠  Could not save results: %v\n", err)
		}
	}

	return nil
}

func mergeResults(results ...scanResult) []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range results {
		for url := range r.hits {
			if !seen[url] {
				seen[url] = true
				out = append(out, url)
			}
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
	return filepath.Join(filepath.Dir(exe), "./", "small-directory-list-20k.txt")
}
