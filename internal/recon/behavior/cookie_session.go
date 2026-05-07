package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/session"
	"net/http"
	"net/url"
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
	if idMeta.Name != knowledge.LiveSession {
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

		// keep in-memory cookies for this run
		ent.SessionCookies[c.Name] = c.Value
		e.sessionCookies[c.Name] = c.Value
	}

	if updated {
		ident.Updated = time.Now()
		if err := session.Save(rawURL, store); err != nil && e.debug {
			println("[session] save failed:", err.Error())
		}
		// Mark entity session as issued/rotated
		ent.SessionIssued = true
	}

	e.discoverIdentityFromResponse(resp)
}

func injectCSRFHeader(req *model.Request, ent *knowledge.Entity, idName string, sessionCookies map[string]string) {
	// prefer the identity's own tracked CSRF token (most accurate)
	if kid := ent.Identities[idName]; kid != nil && kid.HasCSRF && kid.CSRFToken != "" {
		headerName := csrfHeaderName(kid.CSRFCookieName)
		decoded, err := url.QueryUnescape(kid.CSRFToken)
		if err != nil {
			decoded = kid.CSRFToken
		}
		req.Flags.Headers = upsertHeader(req.Flags.Headers, headerName, decoded)
		return
	}
	// fallback: scan engine-level session cookies (first probe on a new entity)
	for name, val := range sessionCookies {
		ln := strings.ToLower(name)
		if strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf") {
			decoded, err := url.QueryUnescape(val)
			if err != nil {
				decoded = val
			}
			req.Flags.Headers = upsertHeader(req.Flags.Headers, csrfHeaderName(name), decoded)
			return
		}
	}
}

func csrfHeaderName(cookieName string) string {
	if strings.Contains(strings.ToUpper(cookieName), "XSRF") {
		return "X-XSRF-TOKEN"
	}
	return "X-CSRF-TOKEN"
}
