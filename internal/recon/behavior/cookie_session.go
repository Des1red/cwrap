package behavior

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/session"
	"net/http"
	"strings"
	"time"
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

func captureSession(ent *knowledge.Entity, idName string, resp *http.Response, rawURL string) {

	store, _ := session.Load(rawURL)

	ident := store.Identities[idName]
	if ident == nil {
		ident = &session.IdentitySession{
			Cookies: make(map[string]*session.CookieEntry),
		}
		store.Identities[idName] = ident
	}

	updated := false

	for _, c := range resp.Cookies() {

		entry := &session.CookieEntry{
			Name:     c.Name,
			Value:    c.Value,
			Source:   "server",
			Path:     c.Path,
			Domain:   c.Domain,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		}

		prev := ident.Cookies[c.Name]
		if prev == nil || prev.Value != c.Value {
			ident.Cookies[c.Name] = entry
			updated = true
		}
		ent.SessionCookies[c.Name] = c.Value
	}

	if updated {
		ident.Updated = time.Now()
		session.Save(rawURL, store)
	}
}
