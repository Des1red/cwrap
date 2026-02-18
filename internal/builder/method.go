package builder

import "strings"

func needsExplicitMethod(method string, hasBody bool) bool {
	method = strings.ToUpper(method)

	switch method {
	case "GET":
		return false

	case "POST":
		// POST with body → curl already knows
		return !hasBody

	default:
		return true
	}
}
