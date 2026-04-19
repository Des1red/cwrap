package behavior

import (
	"cwrap/internal/model"
	"strings"
)

type Identity struct {
	Name      string
	Apply     func(model.Request) model.Request
	Synthetic bool // whether this identity is synthetic (derived) or user-supplied
}

func (e *Engine) identityMeta(name string) (Identity, bool) {
	for _, id := range e.identities {
		if id.Name == name {
			return id, true
		}
	}
	return Identity{}, false
}

func (e *Engine) deriveIdentities(base model.Request) []Identity {

	var ids []Identity

	// baseline (user supplied identity)
	ids = append(ids, Identity{
		Name: "baseline",
		Apply: func(r model.Request) model.Request {
			if len(e.sessionCookies) == 0 {
				return r
			}
			// merge session cookies with any user-supplied cookies
			merged := make(map[string]string)
			// start with session cookies
			for k, v := range e.sessionCookies {
				merged[k] = v
			}
			// overlay user-supplied cookies (they take priority)
			for _, h := range r.Flags.Headers {
				if strings.EqualFold(h.Name, "Cookie") {
					for _, part := range strings.Split(h.Value, "; ") {
						if j := strings.Index(part, "="); j != -1 {
							merged[part[:j]] = part[j+1:]
						}
					}
				}
			}
			r.Flags.Headers = upsertHeader(r.Flags.Headers, "Cookie", cookieHeader(merged))
			return r
		},
	})

	// anonymous (remove auth)
	ids = append(ids, Identity{
		Name:      "anonymous",
		Synthetic: true,
		Apply: func(r model.Request) model.Request {
			r.Flags.Bearer = ""
			r.Flags.Headers = removeAuthHeaders(r.Flags.Headers)
			return r
		},
	})

	// corrupted token
	if base.Flags.Bearer != "" {
		ids = append(ids, Identity{
			Name:      "corrupted-token",
			Synthetic: true,
			Apply: func(r model.Request) model.Request {
				r.Flags.Bearer = r.Flags.Bearer + ".invalid"
				return r
			},
		})
	}

	// fake role
	ids = append(ids, Identity{
		Name:      "fake-admin",
		Synthetic: true,
		Apply: func(r model.Request) model.Request {
			r.Flags.Headers = upsertHeader(r.Flags.Headers, "X-Forwarded-User", "admin")
			return r
		},
	})

	return ids
}

func removeAuthHeaders(h []model.Header) []model.Header {
	out := make([]model.Header, 0, len(h))
	for _, hdr := range h {
		if strings.EqualFold(hdr.Name, "Authorization") || strings.EqualFold(hdr.Name, "Cookie") {
			continue
		}
		out = append(out, hdr)
	}
	return out
}
