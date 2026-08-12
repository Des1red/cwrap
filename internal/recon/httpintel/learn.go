package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
)

// Learn extracts generic HTTP behavior from a response.
// This MUST be shared by api and browser recon.
func Learn(ent *knowledge.Entity, resp *http.Response) {
	learnStatus(ent, resp)
	learnHeaders(ent, resp)
	learnContentType(ent, resp)
	learnSecurityHeaders(ent, resp)
	learnTech(ent, resp)
}
