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

func (e *Engine) captureSession(ent *knowledge.Entity, idMeta Identity, resp *http.Response, rawURL string) {
	// never persist synthetic probe identities
	if idMeta.Synthetic {
		return
	}

	// only persist if the identity actually exists on the entity (was observed)
	id := ent.Identities[idMeta.Name]
	if id == nil {
		return
	}

	// don't persist rejected identities
	if id.Rejected {
		return
	}

	// live identities (discovered accounts like member-uid-2) have frozen
	// cookie snapshots from discovery — never overwrite them from subsequent
	// probes. Still check for newly discoverable identities in the response.
	if idMeta.Name != LiveSession {
		e.discoverIdentityFromResponse(resp)
		return
	}

	store, _ := session.Load(rawURL)

	ident := store.Identities[idMeta.Name]
	if ident == nil {
		ident = &session.IdentitySession{
			Cookies: make(map[string]*session.CookieEntry),
		}
		store.Identities[idMeta.Name] = ident
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

		// always keep in-memory cookies for this run
		ent.SessionCookies[c.Name] = c.Value
		e.sessionCookies[c.Name] = c.Value
	}

	if updated {
		ident.Updated = time.Now()
		session.Save(rawURL, store)
		// Mark entity session as issued/rotated
		ent.SessionIssued = true
	}

	e.discoverIdentityFromResponse(resp)
}
