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

func isStaticAssetURL(u string) bool {
	u = strings.ToLower(u)
	static := []string{
		".js", ".js?", ".js#",
		".css", ".css?",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot",
		".map", ".map?",
	}
	for _, ext := range static {
		if strings.Contains(u, ext) {
			return true
		}
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

		if isStaticAssetURL(link) { // check the link string
			e.k.AddStaticAsset(link)
			continue
		}

		e.k.AddEdge(sourceURL, link, knowledge.EdgeDiscoveredFromJS)

		priority := 50
		switch ep.Method {
		case "POST", "PUT", "PATCH", "DELETE":
			priority = 70
			e.k.Entity(link).Tag(knowledge.SigStateChanging) // target not source
		}

		if isSensitivePath(link) {
			priority += 20
			e.k.Entity(link).Tag(knowledge.SigAdminSurface)
		}

		e.k.PushProbe(ent, knowledge.Probe{
			URL:      link,
			Method:   ep.Method,
			Reason:   "js-" + ep.Kind,
			Priority: priority,
			Created:  time.Now(),
		})
	}
}

// reject URLs where the same path segment repeats more than twice
// this catches infinite relative import resolution loops
func looksLikePathExplosion(u string) bool {
	parts := strings.Split(strings.ToLower(u), "/")
	seen := map[string]int{}
	for _, p := range parts {
		if p == "" {
			continue
		}
		seen[p]++
		if seen[p] > 1 {
			return true
		}
	}
	return false
}
