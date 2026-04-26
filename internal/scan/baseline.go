package scan

import (
	"fmt"
	"net/http"
)

type baseline struct {
	soft404     bool
	trulyStatic bool
	b1          probeResult
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
		soft404:     b1.hash == b2.hash || isSimilarSize(b1.size, b2.size),
		trulyStatic: b1.hash == b2.hash,
		b1:          b1,
	}, nil
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

// buildSubdomainBaseline detects wildcard DNS by probing two random subdomains.
// Reuses the baseline type — soft404=true means the apex has a wildcard catch-all.
func buildSubdomainBaseline(client *http.Client, scheme, apex, port string) (baseline, error) {
	u1 := buildSubdomainURL(scheme, "cwrap-xqzjk-nowildcard", apex, port)
	u2 := buildSubdomainURL(scheme, "cwrap-zvmpt-nowildcard", apex, port)

	b1, err := probe(client, u1)
	if err != nil {
		// A connection error on a random subdomain is expected (NXDOMAIN / refused).
		// Treat as no wildcard.
		return baseline{soft404: false}, nil
	}

	b2, err := probe(client, u2)
	if err != nil {
		return baseline{soft404: false}, nil
	}

	if b1.status != 200 {
		// Wildcard only matters when random subdomains return 200.
		return baseline{soft404: false}, nil
	}

	bl := baseline{
		soft404:     true,
		trulyStatic: b1.hash == b2.hash,
		b1:          b1,
	}
	return bl, nil
}

func (b baseline) printSubdomain() {
	if !b.soft404 {
		return
	}
	if b.trulyStatic {
		fmt.Printf("⚠  Wildcard DNS detected — filtering by exact content match (baseline: %d bytes)\n\n", b.b1.size)
	} else {
		fmt.Printf("⚠  Wildcard DNS detected — responses vary, filtering by size band (baseline: %d bytes)\n\n", b.b1.size)
	}
}
