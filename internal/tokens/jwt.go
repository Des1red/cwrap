package tokens

import (
	"cwrap/internal/exploit/report"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

type JwtClaims map[string]any

func ParseJWT(token string) JwtClaims {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	payload := parts[1]

	// add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	b, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}

	var claims JwtClaims
	if json.Unmarshal(b, &claims) != nil {
		return nil
	}

	return claims
}

func extractRoleFromClaims(c JwtClaims) string {
	if c == nil {
		return ""
	}
	if r, ok := c["role"].(string); ok {
		return strings.ToLower(r)
	}
	return ""
}

func HasJWTInVault(r *report.Report) bool {
	for _, cookies := range r.IdentityVault {
		for _, value := range cookies {
			if strings.Count(value, ".") == 2 {
				return true
			}
		}
	}
	// fall back to session cookies on entities
	for _, ent := range r.Entities {
		for _, sc := range ent.SessionCookies {
			if strings.Count(sc.Value, ".") == 2 {
				return true
			}
		}
	}
	return false
}

func ParseJWTPrincipalUnsafe(token string) (role, uid string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", ""
	}

	if v, ok := claims["role"].(string); ok {
		role = v
	}

	switch v := claims["user_id"].(type) {
	case string:
		uid = v
	case float64:
		uid = strconv.FormatInt(int64(v), 10)
	}

	if uid == "" {
		switch v := claims["sub"].(type) {
		case string:
			uid = v
		case float64:
			uid = strconv.FormatInt(int64(v), 10)
		}
	}

	return role, uid
}

func IsElevatedRole(role string) bool {
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
