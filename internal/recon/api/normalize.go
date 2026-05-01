package api

import (
	"cwrap/internal/recon/linkutil"
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

	if !linkutil.SameSite(base, abs) {
		return "", false
	}

	return abs.String(), true
}
