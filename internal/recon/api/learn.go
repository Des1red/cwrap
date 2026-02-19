package api

import (
	"cwrap/internal/recon/httpintel"
	"net/http"
)

func (e *Engine) learn(url string, resp *http.Response, body []byte) {
	ent := e.k.Entity(url)

	// generic HTTP intelligence (shared with browser recon)
	httpintel.Learn(ent, resp)

	// API-specific intelligence
	if ent.Content.LooksLikeJSON {
		e.extractJSON(ent, body)
	}
}
