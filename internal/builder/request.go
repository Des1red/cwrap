package builder

import (
	"cwrap/internal/model"
	"strings"
)

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

func buildMethod(req model.Request) []string {

	args := []string{}
	hasBody := req.Flags.Body != "" || len(req.Flags.Form) > 0

	if req.Flags.Head {
		args = append(args, "-I")
		return args
	}

	if needsExplicitMethod(req.Method, hasBody) {
		args = append(args, "-X", req.Method)
	}

	return args
}

func buildBody(args []string, req model.Request) []string {

	// HEAD must never send body
	if req.Flags.Head {
		return args
	}

	// multipart overrides raw body
	if req.Flags.Body != "" && len(req.Flags.Form) == 0 {
		args = append(args, "-d", req.Flags.Body)
	}

	return args
}
