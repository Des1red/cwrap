package http

import "strings"

// looksLikeJSONBody detects JSON by inspecting the first non-whitespace byte.
func looksLikeJSONBody(b []byte) bool {
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return c == '{' || c == '['
	}
	return false
}

// looksLikeHTMLBody detects HTML by checking the opening of the document.
func looksLikeHTMLBody(b []byte) bool {
	limit := 512
	if len(b) < limit {
		limit = len(b)
	}
	s := strings.ToLower(strings.TrimSpace(string(b[:limit])))
	return strings.HasPrefix(s, "<!doctype") ||
		strings.HasPrefix(s, "<html") ||
		strings.Contains(s, "<body")
}
