package behavior

import "cwrap/internal/model"

type Identity struct {
	Name  string
	Apply func(model.Request) model.Request
}

func deriveIdentities(base model.Request) []Identity {

	var ids []Identity

	// baseline (user supplied identity)
	ids = append(ids, Identity{
		Name: "baseline",
		Apply: func(r model.Request) model.Request {
			return r
		},
	})

	// anonymous (remove auth)
	ids = append(ids, Identity{
		Name: "anonymous",
		Apply: func(r model.Request) model.Request {
			r.Flags.Bearer = ""
			r.Flags.Headers = removeAuthHeaders(r.Flags.Headers)
			return r
		},
	})

	// corrupted token
	if base.Flags.Bearer != "" {
		ids = append(ids, Identity{
			Name: "corrupted-token",
			Apply: func(r model.Request) model.Request {
				r.Flags.Bearer = r.Flags.Bearer + ".invalid"
				return r
			},
		})
	}

	// fake role
	ids = append(ids, Identity{
		Name: "fake-admin",
		Apply: func(r model.Request) model.Request {
			r.Flags.Headers = append(r.Flags.Headers, model.Header{
				Name:  "X-Forwarded-User",
				Value: "admin",
			})
			return r
		},
	})

	return ids
}

func removeAuthHeaders(h []model.Header) []model.Header {
	out := h[:0]
	for _, hdr := range h {
		if hdr.Name == "Authorization" || hdr.Name == "Cookie" {
			continue
		}
		out = append(out, hdr)
	}
	return out
}
