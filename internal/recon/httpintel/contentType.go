package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
	"strings"
)

// learnContentType classifies the response body's content type and records
// the MIME type seen.
func learnContentType(ent *knowledge.Entity, resp *http.Response) {
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return
	}

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
