package builder

import (
	"cwrap/internal/model"
	"fmt"
	"strings"
)

type Result struct {
	Args    []string
	Cmd     string
	Headers []model.Header
}

func hasAuthorizationHeader(headers []model.Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Authorization") {
			return true
		}
	}
	return false
}

func hasAcceptEncoding(headers []model.Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Accept-Encoding") {
			return true
		}
	}
	return false
}

func hasContentType(headers []model.Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			return true
		}
	}
	return false
}

func Build(req model.Request) Result {
	args := []string{}
	hasBody := req.Flags.Body != "" || len(req.Flags.Form) > 0

	if needsExplicitMethod(req.Method, hasBody) {
		args = append(args, "-X", req.Method)
	}

	// body (only when not multipart)
	if req.Flags.Body != "" && len(req.Flags.Form) == 0 {
		args = append(args, "-d", req.Flags.Body)
	}

	// URL (must exist before headers/options)
	args = append(args, req.URL)
	// multipart form
	if len(req.Flags.Form) > 0 {
		for _, f := range req.Flags.Form {

			val := f.Value

			if f.IsFile {

				// auto mime if not provided
				if !strings.Contains(f.Extra, ";type=") {
					if m := detectMime(f.Value); m != "" {
						f.Extra += ";type=" + m
					}
				}

				val = "@" + val + f.Extra
			} else {
				val += f.Extra
			}

			args = append(args, "-F", fmt.Sprintf("%s=%s", f.Key, val))
		}
	}

	// ---- PROFILE HEADERS ----
	profileHeaders := getProfileHeaders(req.Flags.Profile)

	// merge: profile first, user overrides
	headers := mergeHeaders(profileHeaders, req.Flags.Headers)
	// JSON implies content-type
	if req.Flags.JSON && len(req.Flags.Form) == 0 && !hasContentType(headers) {
		headers = append(headers, model.Header{
			Name:  "Content-Type",
			Value: "application/json",
		})
	}

	// ---- BEARER (only if Authorization not provided) ----
	if req.Flags.Bearer != "" && !hasAuthorizationHeader(headers) {
		headers = append(headers, model.Header{
			Name:  "Authorization",
			Value: "Bearer " + req.Flags.Bearer,
		})
	}

	// ---- HEADERS TO CURL ----
	for _, h := range headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", h.Name, h.Value))
	}

	// enable compression if encoding present
	if hasAcceptEncoding(headers) {
		args = append(args, "--compressed")
	}

	// ---- COOKIES ----
	if len(req.Flags.Cookies) > 0 {
		var parts []string
		for _, c := range req.Flags.Cookies {
			parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		args = append(args, "-b", strings.Join(parts, "; "))
	}

	cmd := buildString(args)

	return Result{
		Args:    args,
		Cmd:     cmd,
		Headers: headers,
	}

}

func buildString(args []string) string {
	parts := make([]string, len(args))

	for i, a := range args {
		parts[i] = shellEscape(a)
	}

	return "curl " + strings.Join(parts, " ")
}

func shellEscape(s string) string {
	if s == "" {
		return "''"
	}

	// safe characters
	if !strings.ContainsAny(s, " \t\n'\"\\$`!&|;<>(){}[]*?~") {
		return s
	}

	// POSIX single-quote escaping
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
