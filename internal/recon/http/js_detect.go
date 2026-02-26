package http

import (
	"cwrap/internal/recon/jsintel"
	"cwrap/internal/recon/knowledge"
	"net/http"
	"strings"
	"time"
)

func looksLikeJS(url string, resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	lct := strings.ToLower(ct)

	if strings.Contains(lct, "javascript") || strings.Contains(lct, "ecmascript") {
		return true
	}

	// fallback: URL suffix
	u := strings.ToLower(url)
	if strings.Contains(u, ".js") {
		return true
	}

	return false
}

func (e *Engine) handleJSEndpoints(
	ent *knowledge.Entity,
	sourceURL string,
	endpoints []jsintel.JSEndpoint,
) {

	for _, ep := range endpoints {

		link, ok := e.normalizeLink(sourceURL, ep.Path)
		if !ok {
			continue
		}

		// Graph edge
		e.k.AddEdge(sourceURL, link, knowledge.EdgeDiscoveredFromJS)

		// Priority base
		priority := 50

		// State-changing methods get higher priority
		switch ep.Method {
		case "POST", "PUT", "PATCH", "DELETE":
			priority = 70
			ent.Tag(knowledge.SigStateChanging)
		}

		// Sensitive/admin paths get boost
		if isSensitivePath(link) {
			priority += 20
			ent.Tag(knowledge.SigAdminSurface)
		}

		ent.ProbeQueue.Push(knowledge.Probe{
			URL:      link,
			Method:   ep.Method,
			Reason:   "js-" + ep.Kind,
			Priority: priority,
			Created:  time.Now(),
		})
	}
}
