package http

import (
	"net/http"
	"strings"
)

func looksLikeJS(url string, resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	lct := strings.ToLower(ct)

	if strings.Contains(lct, "javascript") || strings.Contains(lct, "ecmascript") {
		return true
	}

	// fallback: URL suffix
	u := strings.ToLower(url)
	if strings.Contains(u, ".js") {
		return true
	}

	return false
}
