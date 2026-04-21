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

func pathFamilyPrefix(rawURL string) string {
	prefix := rawURL
	if i := strings.LastIndex(prefix, "/"); i != -1 {
		return prefix[:i+1]
	}
	return prefix
}

func clearSeenPathIDProbeFamily(seen map[string]bool, rawURL string) {
	prefix := pathFamilyPrefix(rawURL)

	for key := range seen {
		if strings.Contains(key, knowledge.ReasonPathIDProbe) && strings.Contains(key, prefix) {
			delete(seen, key)
		}
	}
}
