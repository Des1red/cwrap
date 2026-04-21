package api

import (
	"cwrap/internal/recon/httpintel"
	"cwrap/internal/recon/knowledge"
	"net/http"
	"time"
)

func (e *Engine) learn(url string, resp *http.Response, body []byte) {
	ent := e.k.Entity(url)

	// generic HTTP intelligence (shared with browser recon)
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

	// Json intelligence
	if ent.Content.LooksLikeJSON && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		e.extractJSON(ent, body)
	}
}
