package behavior

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/tokens"
	"fmt"
	"strings"
	"time"
)

func extractJWTIntel(id *knowledge.Identity, claims tokens.JwtClaims) {
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
