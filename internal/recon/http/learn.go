package http

import (
	"cwrap/internal/recon/httpintel"
	"cwrap/internal/recon/jsintel"
	"cwrap/internal/recon/jsonintel"
	"cwrap/internal/recon/knowledge"
	"net/http"
	"time"
)

func (e *Engine) learn(url string, resp *http.Response, body []byte) {

	ent := e.k.Entity(url)

	// generic HTTP intelligence
	httpintel.Learn(ent, resp)

	// ---- follow redirect destinations as new probe targets ----
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			if link, ok := e.normalizeLink(url, loc); ok {
				e.k.AddEdge(url, link, knowledge.EdgeDiscoveredFromHTML)
				e.k.PushProbe(e.k.Entity(url), knowledge.Probe{
					URL:      link,
					Method:   "GET",
					Reason:   knowledge.ReasonRedirect,
					Priority: 80,
					Created:  time.Now(),
				})
			}
		}
	}
	// HTML intelligence
	if ent.Content.LooksLikeHTML {
		e.extractHTML(ent, body)
	}

	// JSON intelligence — extract param keys from JSON response schema
	// The HTTP engine was previously blind to JSON bodies entirely.
	// Any endpoint returning JSON now registers its top-level keys as
	// ParamJSON candidates, feeding expandDiscovery with real signal.
	if ent.Content.LooksLikeJSON && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		jsonintel.ExtractParams(ent, e.k, body)
	}

	// JS intelligence
	if looksLikeJS(url, resp) && !ent.State.JSAnalyzed {
		ent.State.JSAnalyzed = true
		jsEndpoints := jsintel.Learn(ent, url, body)
		e.handleJSEndpoints(ent, url, jsEndpoints)
	}
}
