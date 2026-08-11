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
}
