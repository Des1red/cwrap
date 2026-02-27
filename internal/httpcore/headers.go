package httpcore

import (
	"cwrap/internal/model"
	"strings"
)

func BuildHeaders(req model.Request) []model.Header {
	// merge: profile first, user overrides
	profileHeaders := headers(req.Flags.Profile)

	headers := mergeHeaders(profileHeaders, getContentProfileHeaders(req.Flags.ContentProfile))
	headers = mergeHeaders(headers, req.Flags.Headers)
	if !hasBody(req) {
		headers = removeHeader(headers, "Content-Type")
	}
	if req.Flags.JSON && len(req.Flags.Form) == 0 && !hasContentType(headers) {
		headers = append(headers, model.Header{
			Name:  "Content-Type",
			Value: "application/json",
		})
	}

	if req.Flags.Bearer != "" && !hasAuthorizationHeader(headers) {
		headers = append(headers, model.Header{
			Name:  "Authorization",
			Value: "Bearer " + req.Flags.Bearer,
		})
	}

	return headers
}

func removeHeader(headers []model.Header, name string) []model.Header {
	out := make([]model.Header, 0, len(headers))
	for _, h := range headers {
		if !strings.EqualFold(h.Name, name) {
			out = append(out, h)
		}
	}
	return out
}
func hasBody(req model.Request) bool {
	if req.Flags.Head {
		return false
	}

	if len(req.Flags.Form) > 0 {
		return true
	}

	if req.Flags.Body != "" {
		return true
	}

	if req.Flags.JSON {
		return true
	}

	return false
}
