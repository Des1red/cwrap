package http

import (
	"net/url"
	"strings"
)

func (e *Engine) normalizeLink(baseURL, raw string) (string, bool) {

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	// ignore fragments only
	if strings.HasPrefix(raw, "#") {
		return "", false
	}

	// ignore JS / mail links
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

	// remove fragment
	abs.Fragment = ""

	// optional: restrict to same host
	if abs.Host != base.Host {
		return "", false
	}

	return abs.String(), true
}
