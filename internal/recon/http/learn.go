package http

import (
	"cwrap/internal/recon/httpintel"
	"cwrap/internal/recon/jsintel"
	"net/http"
)

func (e *Engine) learn(url string, resp *http.Response, body []byte) {

	ent := e.k.Entity(url)

	// generic HTTP intelligence
	httpintel.Learn(ent, resp)

	// HTML intelligence
	if ent.Content.LooksLikeHTML {
		e.extractHTML(ent, body)
	}

	// JS intelligence
	if looksLikeJS(url, resp) {

		jsEndpoints := jsintel.Learn(ent, url, body)

		e.handleJSEndpoints(ent, url, jsEndpoints)
	}
}
