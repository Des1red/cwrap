package tokens

import (
	"cwrap/internal/exploit/report"
	"strings"
)

func ResolveTokenPrincipal(id *report.ReportIdentity, jar map[string]string) (role, uid string) {
	if id != nil {
		if id.Role != "" || id.UserID != "" {
			return id.Role, id.UserID
		}
	}

	token := jar["auth_token"]
	if token == "" {
		return "", ""
	}

	role, uid = ParseJWTPrincipalUnsafe(token)
	return role, uid
}

func FirstCookieValue(jar map[string]string) string {
	for _, v := range jar {
		if strings.Count(v, ".") == 2 {
			return v // prefer JWT
		}
	}
	for _, v := range jar {
		return v // fallback to first
	}
	return ""
}
