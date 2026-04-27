package scan

import (
	"cwrap/internal/model"
	"fmt"
	"strings"
)

func Run(req model.Request) error {
	if req.URL == "" {
		return fmt.Errorf("scan requires a URL — cwrap scan <url>")
	}

	doDirScan := validateDirScan(&req) == nil
	doSubdomainScan := validateSubdomainScan(&req) == nil

	if !doDirScan && !doSubdomainScan {
		return fmt.Errorf("nothing to scan — no wordlists available for either mode")
	}

	base := strings.TrimRight(req.URL, "/")
	scanClient := newClient(req)

	bf, err := buildBaseline(scanClient, base)
	if err != nil {
		return err
	}
	bf.print()

	r1, r2, r3 := newScanResult(), newScanResult(), newScanResult()

	if doDirScan {
		fmt.Printf("═══ Stage 1 — Directory Discovery ═══\n\n")
		r1 = stageOne(scanClient, base, req.FilePath, bf)
		if len(r1.dirs) > 0 {
			fmt.Printf("\n═══ Stage 2 — Subdirectory Expansion (%d directories) ═══\n\n", len(r1.dirs))
			r2 = stageTwo(scanClient, r1.dirs, req.FilePath, bf, req.Flags.Debug)
		} else {
			fmt.Printf("\n═══ Stage 2 — Subdirectory Expansion ═══\n\n")
			fmt.Printf("  skipped — no expandable 200 directories found\n")
		}
	}

	if doSubdomainScan {
		fmt.Printf("\n═══ Stage 3 — Subdomain Enumeration ═══\n\n")
		switch reason := subdomainSkipReason(base, req.SubdomainFile); reason {
		case "":
			r3 = stageThree(scanClient, base, req.SubdomainFile)
		default:
			fmt.Printf("  skipped — %s\n", reason)
		}
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
