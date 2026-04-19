package behavior

import (
	"cwrap/internal/recon/knowledge"
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
				extractJWTIntel(id, parseJWT(c.Value))
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
			extractJWTIntel(id, parseJWT(c.Value))
		}
	}

	// ---- auth scheme ----
	auth := resp.Request.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		id.AuthScheme = "bearer"

		extractJWTIntel(id, parseJWT(strings.TrimPrefix(auth, "Bearer ")))
	} else if strings.HasPrefix(auth, "Basic ") {
		id.AuthScheme = "basic"
	}

	// ---- csrf ----
	if resp.Header.Get("X-CSRF-Token") != "" || resp.Header.Get("X-XSRF-Token") != "" {
		id.HasCSRF = true
	}
	// ---- rejection ----
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		id.Rejected = true
	}
	if id.IssuedByServer || id.AuthScheme != "" {
		ent.HTTP.AuthLikely = true
	}

	// ---- classify kind (simple + useful) ----
	switch {
	case id.Rejected:
		id.Kind = knowledge.IdentityInvalid
	case id.Role != "" && isElevatedRole(id.Role):
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

func isElevatedRole(role string) bool {
	r := strings.ToLower(role)

	switch {
	case strings.Contains(r, "admin"),
		strings.Contains(r, "root"),
		strings.Contains(r, "super"),
		strings.Contains(r, "staff"),
		strings.Contains(r, "mod"),
		strings.Contains(r, "owner"):
		return true
	}
	return false
}
