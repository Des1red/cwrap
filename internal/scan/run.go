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
	plainClient := newPlainClient() // baseline only — no auth headers
	scanClient := newClient(req)    // real probes — full auth stack

	bf, err := buildBaseline(scanClient, base)
	if err != nil {
		return err
	}
	bf.print()

	fmt.Printf("═══ Stage 1 — Directory Discovery ═══\n\n")
	r1 := stageOne(scanClient, base, req.FilePath, bf)

	r2 := newScanResult()
	if len(r1.dirs) > 0 {
		fmt.Printf("\n═══ Stage 2 — Subdirectory Expansion (%d directories) ═══\n\n", len(r1.dirs))
		r2 = stageTwo(scanClient, r1.dirs, req.FilePath, bf)
	} else {
		fmt.Printf("\n═══ Stage 2 — Subdirectory Expansion ═══\n\n")
		fmt.Printf("  skipped — no expandable 200 directories found\n")
	}

	// ── Stage 3 — Subdomain Enumeration ──────────────────────────────────────
	fmt.Printf("\n═══ Stage 3 — Subdomain Enumeration ═══\n\n")
	r3 := newScanResult()

	switch reason := subdomainSkipReason(base, req.SubdomainFile); reason {
	case "":
		subFile := resolveSubdomainFile(req.SubdomainFile)
		r3 = stageThree(plainClient, base, subFile)
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
