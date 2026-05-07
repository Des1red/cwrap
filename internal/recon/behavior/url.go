package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"net/url"
	"strings"
)

func extractCurrentValue(raw, key string) string {

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	return u.Query().Get(key)
}

func clearSeenPathIDProbeFamily(rootSeen map[string]bool, ent *knowledge.Entity, rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	tmpl := pathTemplate(u) // e.g. "/api/users/{id}"

	clearByTemplate := func(seen map[string]bool) {
		for key := range seen {
			if !strings.Contains(key, knowledge.ReasonPathIDProbe) {
				continue
			}
			// key format: METHOD|URL|REASON|...
			parts := strings.SplitN(key, "|", 3)
			if len(parts) < 2 {
				continue
			}
			ku, err := url.Parse(parts[1])
			if err != nil {
				continue
			}
			if pathTemplate(ku) == tmpl {
				delete(seen, key)
			}
		}
	}

	clearByTemplate(rootSeen)
	clearByTemplate(ent.SeenProbes)
}

func probeLogURL(req model.Request) string {
	if len(req.Flags.Query) == 0 {
		return req.URL
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return req.URL
	}

	q := u.Query()
	for _, p := range req.Flags.Query {
		if p.Key == "" {
			continue
		}
		q.Set(p.Key, p.Value)
	}

	u.RawQuery = q.Encode()
	return u.String()
}

func (e *Engine) registerURLQueryParams(ent *knowledge.Entity) {
	if ent == nil || ent.URL == "" {
		return
	}

	u, err := url.Parse(ent.URL)
	if err != nil {
		return
	}

	q := u.Query()
	if len(q) == 0 {
		return
	}

	for name := range q {
		if name == "" {
			continue
		}

		ent.AddParam(name, knowledge.ParamQuery)
		e.k.AddParam(name)
		e.int.ClassifyParam(ent, name)
		ent.Tag(knowledge.SigHasQueryParams)
	}
}
