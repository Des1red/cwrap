package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"fmt"
	"net/http"
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

	// session (user supplied identity)
	ids = append(ids, Identity{
		Name: "session",
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

func (e *Engine) addLiveIdentity(name string, cookies map[string]string, roleUID string) {
	// check if identity with this name already exists
	for _, id := range e.identities {
		if id.Name == name {
			return
		}
	}

	if e.debug {
		println("== New identity discovered:", name, "==")
	}
	// register so subsequent probes with same role are blocked
	e.knownRoleUIDs[roleUID] = true
	// snapshot cookies so the closure is stable
	snapshot := make(map[string]string, len(cookies))
	for k, v := range cookies {
		snapshot[k] = v
	}

	e.identities = append(e.identities, Identity{
		Name:      name,
		Synthetic: false,
		Apply: func(r model.Request) model.Request {
			// remove any existing cookie header first
			r.Flags.Headers = removeAuthHeaders(r.Flags.Headers)
			// inject this identity's specific cookies
			if ck := cookieHeader(snapshot); ck != "" {
				r.Flags.Headers = upsertHeader(r.Flags.Headers, "Cookie", ck)
			}
			return r
		},
	})

	// re-queue all currently known entities for this new identity
	root := e.k.Entity(e.k.Target)
	for _, ent := range e.k.Entities {
		if ent == nil || !ent.State.Seen {
			continue
		}
		e.k.PushProbe(root, knowledge.Probe{
			URL:      ent.URL,
			Method:   "GET",
			Reason:   knowledge.ReasonIdentityProbe,
			Priority: 160,
		})
	}
	// clear probed path templates so expandPathIDs re-runs on organically
	// discovered entities with the new identity's perspective
	for tmpl := range e.probedPathTemplates {
		delete(e.probedPathTemplates, tmpl)
	}

	// re-queue path ID expansion for all seen entities that have path params
	for _, ent := range e.k.Entities {
		if ent == nil || !ent.State.Seen {
			continue
		}
		// only re-expand entities that had path ID params discovered
		hasPP := false
		for _, p := range ent.Params {
			if p != nil && p.Sources[knowledge.ParamPath] {
				hasPP = true
				break
			}
		}
		if !hasPP {
			continue
		}
		// reset so expandPathIDs runs again for this entity
		ent.State.PathIDProbed = false

		// allow sibling/generated path-ID probes for the same route family
		// to rerun under the new identity
		clearSeenPathIDProbeFamily(root.SeenProbes, ent.URL)

		e.k.PushProbe(root, knowledge.Probe{
			URL:      ent.URL,
			Method:   "GET",
			Reason:   knowledge.ReasonIdentityProbe,
			Priority: 155, // slightly below identity probes, above normal expansion
		})
	}
}

// discoverIdentityFromResponse checks if a response contains a JWT cookie
// that belongs to a previously unseen role+uid combination, and if so
// registers it as a new live identity.
func (e *Engine) discoverIdentityFromResponse(resp *http.Response) {
	var newRole, newUID string
	var newCookies = map[string]string{}

	for _, c := range resp.Cookies() {
		newCookies[c.Name] = c.Value
		if strings.Count(c.Value, ".") == 2 {
			claims := parseJWT(c.Value)
			if claims != nil {
				if r, ok := claims["role"].(string); ok {
					newRole = strings.ToLower(r)
				}
				if u, ok := claims["user_id"]; ok {
					newUID = fmt.Sprintf("%v", u)
				}
			}
		}
	}

	if newRole == "" && newUID == "" {
		return
	}

	roleUID := newRole + "|" + newUID
	if e.knownRoleUIDs[roleUID] || e.discoveredIdentities[roleUID] {
		return
	}

	e.discoveredIdentities[roleUID] = true
	e.addLiveIdentity(fmt.Sprintf("%s-uid-%s", newRole, newUID), newCookies, roleUID)
}
