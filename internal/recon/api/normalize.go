package api

import (
	"net/url"
	"strings"
)

func (e *Engine) normalizeLink(baseURL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	if strings.HasPrefix(raw, "#") {
		return "", false
	}

	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") {
		return "", false
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}

	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	abs := base.ResolveReference(ref)
	abs.Fragment = ""

	if abs.Host != base.Host {
		return "", false
	}

	return abs.String(), true
}
