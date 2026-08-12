package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
	"strings"
)

// learnHeaders scans response headers for auth and CSRF indicators, and
// registers every header name seen on the entity.
func learnHeaders(ent *knowledge.Entity, resp *http.Response) {
	for name := range resp.Header {
		ent.AddHeader(name)

		ln := strings.ToLower(name)

		switch ln {

		// authentication indicators
		case "www-authenticate":
			ent.HTTP.AuthLikely = true

		// csrf indicators
		case "x-csrf-token", "x-xsrf-token", "csrf-token":
			ent.HTTP.CSRFPresent = true

		case "set-cookie":
			for _, c := range resp.Cookies() {
				ln := strings.ToLower(c.Name)
				if strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf") {
					ent.HTTP.CSRFPresent = true
					break
				}
			}
		}
	}

	learnAuthScheme(ent, resp)
	learnCORS(ent, resp)
}

// learnCORS flags permissive cross-origin configurations: a response that
// allows credentialed requests (Access-Control-Allow-Credentials: true)
// combined with either a wildcard Allow-Origin, or an Allow-Origin that
// reflects the request's Origin verbatim. The wildcard+credentials
// combination is invalid per the Fetch spec and modern browsers reject it,
// but misconfigured servers still send it — worth flagging as evidence of
// a broader misconfiguration even if not directly exploitable in-browser.
// The reflected-origin case is the actually dangerous one: any origin can
// make authenticated cross-origin requests.
func learnCORS(ent *knowledge.Entity, resp *http.Response) {
	origin := resp.Header.Get("Access-Control-Allow-Origin")
	if origin == "" {
		return
	}

	credentialed := strings.EqualFold(
		resp.Header.Get("Access-Control-Allow-Credentials"),
		"true",
	)
	if !credentialed {
		return
	}

	wildcard := origin == "*"

	reflected := false
	if resp.Request != nil {
		if reqOrigin := resp.Request.Header.Get("Origin"); reqOrigin != "" {
			reflected = origin == reqOrigin
		}
	}

	if wildcard || reflected {
		ent.HTTP.CORSPermissive = true
		ent.HTTP.CORSOrigin = origin
		ent.Tag(knowledge.SigPermissiveCORS)
	}
}

// learnAuthScheme extracts the auth scheme token from a WWW-Authenticate
// challenge, e.g. "Bearer realm=\"api\"" -> "bearer". A server can send
// multiple challenges in one header (RFC 7235 allows comma-separated
// challenges) or across repeated headers — this takes the first scheme
// token found and stops there, since the goal is knowing *which* auth
// mechanisms are in play, not exhaustively enumerating every challenge
// parameter.
func learnAuthScheme(ent *knowledge.Entity, resp *http.Response) {
	value := resp.Header.Get("WWW-Authenticate")
	if value == "" {
		return
	}

	fields := strings.Fields(value)
	if len(fields) == 0 {
		return
	}

	scheme := strings.ToLower(strings.TrimSuffix(fields[0], ","))
	if scheme == "" {
		return
	}

	ent.HTTP.AuthScheme = scheme
}
