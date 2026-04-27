package curl

import (
	"cwrap/internal/model"
	"net/url"
	"strings"
)

func appendHeaderArgs(args []string, headers []model.Header) []string {
	for _, h := range headers {
		args = append(args, "-H", h.Name+": "+h.Value)
	}
	return args
}

func csrfHeaderName(cookie string) string {

	switch strings.ToLower(cookie) {

	case "csrftoken":
		return "X-CSRFToken"

	case "xsrf-token":
		return "X-XSRF-TOKEN"

	case "_csrf":
		return "X-CSRF-Token"

	default:
		return "X-CSRF-Token"
	}
}
func applyCSRFHeader(req model.Request, headers []model.Header) []model.Header {

	if !req.Flags.CSRF {
		return headers
	}

	host := requestHost(req.URL)

	name, token := readCSRFCookie(host)

	if token == "" {
		return headers
	}

	header := csrfHeaderName(name)

	headers = append(headers, model.Header{
		Name:  header,
		Value: token,
	})

	return headers
}
func requestHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
