package behavior

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/tokens"
	"net/http"
	"strings"
)

func extractIdentity(ent *knowledge.Entity, name string, resp *http.Response) {
	id := &knowledge.Identity{Name: name}

	// ---- what client SENT ----
	sentAuth := resp.Request.Header.Get("Authorization") != ""
	sentCookie := resp.Request.Header.Get("Cookie") != ""
	// ---- parse SENT cookies ----
	if sentCookie {
		for _, c := range resp.Request.Cookies() {
			if strings.Count(c.Value, ".") == 2 {
				extractJWTIntel(id, tokens.ParseJWT(c.Value))
			}
		}
	}

	id.SentCreds = sentAuth || sentCookie
	seen := map[string]bool{}
	// ---- cookies ISSUED by server (Set-Cookie) ----
	for _, c := range resp.Cookies() {
		if !seen[c.Name] {
			id.CookieNames = append(id.CookieNames, c.Name)
			seen[c.Name] = true
		}
		id.IssuedByServer = true
		// try parse cookie as JWT
		if strings.Count(c.Value, ".") == 2 {
			extractJWTIntel(id, tokens.ParseJWT(c.Value))
		}
	}

	// ---- auth scheme ----
	auth := resp.Request.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		id.AuthScheme = "bearer"

		extractJWTIntel(id, tokens.ParseJWT(strings.TrimPrefix(auth, "Bearer ")))
	} else if strings.HasPrefix(auth, "Basic ") {
		id.AuthScheme = "basic"
	}

	// ---- csrf ----
	// ---- csrf ----
	// check response headers first
	if token := resp.Header.Get("X-CSRF-Token"); token != "" {
		id.HasCSRF = true
		id.CSRFToken = token
		id.CSRFHeader = "X-CSRF-Token"
	} else if token := resp.Header.Get("X-XSRF-Token"); token != "" {
		id.HasCSRF = true
		id.CSRFToken = token
		id.CSRFHeader = "X-XSRF-Token"
	}

	// check Set-Cookie for csrf cookies
	for _, c := range resp.Cookies() {
		ln := strings.ToLower(c.Name)
		if strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf") {
			id.HasCSRF = true
			id.CSRFToken = c.Value
			id.CSRFCookieName = c.Name
		}
	}
	// ---- rejection ----
	if resp.StatusCode == 401 {
		id.Rejected = true
	}
	if id.IssuedByServer || id.AuthScheme != "" {
		ent.HTTP.AuthLikely = true
	}

	// ---- classify kind (simple + useful) ----
	switch {
	case id.Rejected:
		id.Kind = knowledge.IdentityInvalid
	case id.Role != "" && tokens.IsElevatedRole(id.Role):
		id.Kind = knowledge.IdentityElevated
	case id.IssuedByServer && resp.StatusCode >= 300 && resp.StatusCode < 400:
		id.Kind = knowledge.IdentityBootstrap
	case id.IssuedByServer:
		id.Kind = knowledge.IdentityUser
	case !sentAuth && !sentCookie:
		id.Kind = knowledge.IdentityNone
	default:
		id.Kind = knowledge.IdentityUser
	}

	// ---- preserve across probes ----
	if prev, ok := ent.Identities[name]; ok && prev != nil {
		if prev.Effective {
			id.Effective = true
		}
		if prev.SentCreds {
			id.SentCreds = true
		}
		if id.CSRFToken == "" && prev.CSRFToken != "" {
			id.CSRFToken = prev.CSRFToken
			id.HasCSRF = true
		}
		if id.Role == "" && prev.Role != "" {
			id.Role = prev.Role
		}
		if id.UserID == "" && prev.UserID != "" {
			id.UserID = prev.UserID
		}
		if id.Expiry == "" && prev.Expiry != "" {
			id.Expiry = prev.Expiry
		}
		if id.TokenJTI == "" && prev.TokenJTI != "" {
			id.TokenJTI = prev.TokenJTI
		}
	}
	ent.AddIdentity(id)
}
