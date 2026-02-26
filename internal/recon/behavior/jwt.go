package behavior

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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
