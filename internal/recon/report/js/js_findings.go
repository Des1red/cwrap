package js

import (
	"cwrap/internal/recon/knowledge"
	"sort"
	"strings"
)

func ReportableJSFindingKeys(
	ent *knowledge.Entity,
) []string {
	if ent == nil {
		return nil
	}

	keys := make([]string, 0)

	for key, count := range ent.Content.JSFindings {
		if count <= 0 || hideJSFindingFromReport(key) {
			continue
		}

		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func hideJSFindingFromReport(key string) bool {
	if strings.HasPrefix(key, "ast_") {
		return true
	}

	switch key {
	case "email",
		"endpoint",
		"http_flow":
		return true
	}

	// Endpoint totals already appear in the discovery and
	// route trees, so endpoint_literal and other endpoint
	// implementation counters are redundant here.
	return strings.HasPrefix(key, "endpoint_")
}
