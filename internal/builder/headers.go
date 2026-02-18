package builder

import "cwrap/internal/model"

func buildHeaders(req model.Request) []model.Header {
	// merge: profile first, user overrides
	profileHeaders := getProfileHeaders(req.Flags.Profile)

	headers := mergeHeaders(profileHeaders, getContentProfileHeaders(req.Flags.ContentProfile))
	headers = mergeHeaders(headers, req.Flags.Headers)

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

func appendHeaderArgs(args []string, headers []model.Header) []string {
	for _, h := range headers {
		args = append(args, "-H", h.Name+": "+h.Value)
	}
	return args
}
