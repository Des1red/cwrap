package behavior

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"strings"
)

func extractCurrentValue(raw, key string) string {

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	return u.Query().Get(key)
}

func clearSeenPathIDProbeFamily(rootSeen map[string]bool, ent *knowledge.Entity, rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	tmpl := pathTemplate(u) // e.g. "/api/users/{id}"

	clearByTemplate := func(seen map[string]bool) {
		for key := range seen {
			if !strings.Contains(key, knowledge.ReasonPathIDProbe) {
				continue
			}
			// key format: METHOD|URL|REASON|...
			parts := strings.SplitN(key, "|", 3)
			if len(parts) < 2 {
				continue
			}
			ku, err := url.Parse(parts[1])
			if err != nil {
				continue
			}
			if pathTemplate(ku) == tmpl {
				delete(seen, key)
			}
		}
	}

	clearByTemplate(rootSeen)
	clearByTemplate(ent.SeenProbes)
}
