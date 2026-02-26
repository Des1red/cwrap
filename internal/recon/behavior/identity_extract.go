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
	// ---- parse SENT cookies too (not only Set-Cookie) ----
	if sentCookie {
		for _, c := range resp.Request.Cookies() {
			// optional: track sent cookie names (dedupe like you did for issued)
			// id.SentCookieNames = append(...)

			// try parse JWT-like cookies (auth_token / refresh_token)
			if strings.Count(c.Value, ".") == 2 {
				claims := parseJWT(c.Value)
				role := extractRoleFromClaims(claims)
				if role != "" {
					id.Role = role
				}
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
			claims := parseJWT(c.Value)
			role := extractRoleFromClaims(claims)
			if role != "" {
				id.Role = role
			}
		}
	}

	// ---- auth scheme ----
	auth := resp.Request.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		id.AuthScheme = "bearer"

		token := strings.TrimPrefix(auth, "Bearer ")
		claims := parseJWT(token)
		role := extractRoleFromClaims(claims)
		if role != "" {
			id.Role = role
		}
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
	if prev, ok := ent.Identities[name]; ok && prev != nil && prev.Effective {
		id.Effective = true
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
		strings.Contains(r, "mod"):
		return true
	}
	return false
}
