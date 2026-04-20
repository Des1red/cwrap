package behavior

import (
	"cwrap/internal/recon/knowledge"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type jwtClaims map[string]any

func parseJWT(token string) jwtClaims {
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

	var claims jwtClaims
	if json.Unmarshal(b, &claims) != nil {
		return nil
	}

	return claims
}

func extractRoleFromClaims(c jwtClaims) string {
	if c == nil {
		return ""
	}
	if r, ok := c["role"].(string); ok {
		return strings.ToLower(r)
	}
	return ""
}

func extractJWTIntel(id *knowledge.Identity, claims jwtClaims) {
	if claims == nil {
		return
	}
	// top-level claims (HS256 style)
	if r, ok := claims["role"].(string); ok {
		id.Role = strings.ToLower(r)
	}
	if uid, ok := claims["user_id"]; ok {
		id.UserID = fmt.Sprintf("%v", uid)
	}
	if exp, ok := claims["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0)
		id.Expiry = t.UTC().Format("2006-01-02 15:04")
	}
	if jti, ok := claims["jti"].(string); ok {
		id.TokenJTI = jti
	}
	// nested data claims (RS256 style — Juice Shop)
	if data, ok := claims["data"].(map[string]any); ok {
		if r, ok := data["role"].(string); ok && id.Role == "" {
			id.Role = strings.ToLower(r)
		}
		if uid, ok := data["id"]; ok && id.UserID == "" {
			id.UserID = fmt.Sprintf("%v", uid)
		}
	}
}
