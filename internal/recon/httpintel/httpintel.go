package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
	"strings"
)

// Learn extracts generic HTTP behavior from a response.
// This MUST be shared by api and browser recon.
func Learn(ent *knowledge.Entity, resp *http.Response) {

	// ---- status tracking ----
	ent.Content.Statuses[resp.StatusCode]++

	// ---- headers ----
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
			for _, v := range resp.Header.Values(name) {
				lv := strings.ToLower(v)
				if strings.Contains(lv, "csrf") || strings.Contains(lv, "xsrf") {
					ent.HTTP.CSRFPresent = true
					break
				}
			}
		}
	}

	// ---- content-type ----
	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		base := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
		if base == "" {
			base = strings.ToLower(strings.TrimSpace(ct))
		}

		ent.Content.MIMEs[base]++

		if strings.Contains(base, "json") {
			ent.Content.LooksLikeJSON = true
			ent.Tag(knowledge.SigHasJSONBody)
		}

		if strings.Contains(base, "html") {
			ent.Content.LooksLikeHTML = true
		}

		if strings.Contains(base, "xml") {
			ent.Content.LooksLikeXML = true
		}
	}

	// ---- auth boundary ----
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		ent.HTTP.AuthLikely = true
		ent.Tag(knowledge.SigAuthBoundary)
	}
}
