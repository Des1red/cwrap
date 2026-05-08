package tokens

import (
	"strings"
)

func FirstCookieValue(jar map[string]string) string {
	for _, v := range jar {
		if LooksLikeJWT(v) {
			return v // prefer JWT
		}
	}
	for _, v := range jar {
		return v // fallback to first
	}
	return ""
}

func LooksLikeOpaqueAuthCookie(name, value string) bool {
	if value == "" || len(value) < 8 {
		return false
	}

	if LooksLikeJWT(value) {
		return false
	}

	n := strings.ToLower(name)

	return strings.Contains(n, "session") ||
		strings.Contains(n, "auth") ||
		strings.Contains(n, "token") ||
		strings.Contains(n, "remember") ||
		n == "sid" ||
		strings.HasSuffix(n, "_sid") ||
		strings.HasSuffix(n, "-sid")
}

func LooksLikeJWT(v string) bool {
	return strings.Count(v, ".") == 2
}
