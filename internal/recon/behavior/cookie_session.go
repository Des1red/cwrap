package behavior

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/session"
	"net/http"
	"strings"
)

// build a single Cookie header value
func cookieHeader(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for k, v := range cookies {
		parts = append(parts, k+"="+v)
	}
	// optional: sort.Strings(parts) for determinism
	return strings.Join(parts, "; ")
}

func captureSession(ent *knowledge.Entity, resp *http.Response, rawURL string) {

	updated := false

	for _, c := range resp.Cookies() {

		if ent.SessionCookies[c.Name] != c.Value {
			ent.SessionCookies[c.Name] = c.Value
			ent.SessionIssued = true
			updated = true
		}
	}

	if updated {
		var out session.Store
		for name, value := range ent.SessionCookies {
			out.Cookies = append(out.Cookies, session.Cookie{
				Name:  name,
				Value: value,
			})
		}
		session.Save(rawURL, &out)
	}
}
