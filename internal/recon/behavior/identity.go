package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/tokens"
	"fmt"
	"net/http"
	"net/url"
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
		Name: knowledge.LiveSession,
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
		Name:      knowledge.Anonymous,
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
			Name:      knowledge.CorruptedToken,
			Synthetic: true,
			Apply: func(r model.Request) model.Request {
				r.Flags.Headers = removeAuthHeaders(r.Flags.Headers)
				r.Flags.Bearer = r.Flags.Bearer + ".invalid"
				return r
			},
		})
	}

	// corrupted-cookie-token is also added dynamically after session capture.
	// Initial creation here only covers cookies already known at scan start.
	baseCookies := mergedBaseCookies(base, e.sessionCookies)
	if corruptedCookies, ok := corruptJWTCookies(baseCookies); ok {
		ids = append(ids, corruptedCookieIdentity(knowledge.CorruptedCookieToken, corruptedCookies))
	}

	if corruptedCookies, ok := corruptOpaqueCookies(baseCookies); ok {
		ids = append(ids, corruptedCookieIdentity(knowledge.CorruptedOpaqueCookieToken, corruptedCookies))
	}

	// fake role
	ids = append(ids, Identity{
		Name:      knowledge.FakeAdmin,
		Synthetic: true,
		Apply: func(r model.Request) model.Request {
			r.Flags.Bearer = ""
			r.Flags.Headers = removeAuthHeaders(r.Flags.Headers)
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

// corruptedCookieIdentity builds a synthetic Identity that strips existing
// auth headers and injects the given (already-corrupted) cookie set. Used
// for both JWT-signature corruption and opaque-cookie corruption — the two
// variants differ only in which pre-corrupted cookie map they're built
// from, not in how the resulting identity behaves.
func corruptedCookieIdentity(name string, cookies map[string]string) Identity {
	return Identity{
		Name:      name,
		Synthetic: true,
		Apply: func(r model.Request) model.Request {
			r.Flags.Bearer = ""
			r.Flags.Headers = removeAuthHeaders(r.Flags.Headers)

			if ck := cookieHeader(cookies); ck != "" {
				r.Flags.Headers = upsertHeader(r.Flags.Headers, "Cookie", ck)
			}

			return r
		},
	}
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
	e.k.DiscoveredIdentities[name] = snapshot

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
	reason := knowledge.ReasonLiveIdentityRefresh + ":" + name
	// Tracks entities already re-queued via their own direct self-probe
	// below, so the fallback loop further down doesn't push a plain probe
	// that re-triggers the same self-probe a second time through Expand.
	handled := make(map[string]bool, len(e.k.Entities))

	// replace the existing re-queue block for path param entities
	for _, ent := range e.k.Entities {
		if ent == nil || !ent.State.Seen {
			continue
		}

		pathParams := extractPathParams(ent)
		if len(pathParams) == 0 {
			continue
		}
		handled[ent.URL] = true

		// reset so expandPathIDs re-runs for this entity under the new identity
		ent.State.PathIDProbed = false
		clearSeenPathIDProbeFamily(root.SeenProbes, ent, ent.URL)
		if e.debug {
			fmt.Printf("[debug addLiveIdentity] queuing %s pathParams=%v\n", ent.URL, pathParams)
		}
		// push with PathParams so storeResponse populates IdentityAccess/IdentityDenied
		e.k.PushProbe(root, knowledge.Probe{
			URL:          ent.URL,
			Method:       "GET",
			PathParams:   pathParams,
			Reason:       reason,
			Priority:     155,
			IdentityKind: knowledge.ProbeIdentityLive,
		})
	}
	// clear probed path templates so expandPathIDs re-runs on organically
	// discovered entities with the new identity's perspective
	for tmpl := range e.probedPathTemplates {
		delete(e.probedPathTemplates, tmpl)
	}

	// Fallback: re-queue path ID expansion for seen entities that carry a
	// ParamPath-sourced param but weren't already covered by the loop
	// above — e.g. a URL that's been rewritten/normalized so its raw path
	// no longer exposes the ID segment directly, even though the param
	// was registered by an earlier expandPathIDs run. Entities already
	// handled above are skipped to avoid pushing a redundant probe that
	// re-triggers the same self-probe a second time.
	for _, ent := range e.k.Entities {

		if ent == nil || !ent.State.Seen || handled[ent.URL] {
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
		clearSeenPathIDProbeFamily(root.SeenProbes, ent, ent.URL)
		e.k.PushProbe(root, knowledge.Probe{
			URL:          ent.URL,
			Method:       "GET",
			Reason:       reason,
			Priority:     155, // slightly below identity probes, above normal expansion
			IdentityKind: knowledge.ProbeIdentityLive,
		})
	}
}

func extractPathParams(ent *knowledge.Entity) map[string]string {
	u, err := url.Parse(ent.URL)
	if err != nil {
		return nil
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	out := map[string]string{}
	for i, seg := range segments {
		if !looksLikePathID(seg) {
			continue
		}
		name := "id"
		if i > 0 {
			parent := strings.ToLower(segments[i-1])
			if strings.HasSuffix(parent, "s") && len(parent) > 2 {
				parent = parent[:len(parent)-1]
			}
			name = parent + "_id"
		}
		out[name] = seg
	}
	return out
}

// discoverIdentityFromResponse checks if a response contains a JWT cookie
// that belongs to a previously unseen role+uid combination, and if so
// registers it as a new live identity.
func (e *Engine) discoverIdentityFromResponse(resp *http.Response) {
	var newRole, newUID string
	var newCookies = map[string]string{}

	for _, c := range resp.Cookies() {
		newCookies[c.Name] = c.Value
		if tokens.LooksLikeJWT(c.Value) {
			claims := tokens.ParseJWT(c.Value)
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

func (e *Engine) ensureCorruptedCookieIdentity(base model.Request) {
	baseCookies := mergedBaseCookies(base, e.sessionCookies)

	corruptedCookies, ok := corruptJWTCookies(baseCookies)
	if !ok {
		return
	}

	for _, id := range e.identities {
		if id.Name == knowledge.CorruptedCookieToken {
			return
		}
	}

	if e.debug {
		println("== New synthetic identity discovered:", knowledge.CorruptedCookieToken, "==")
	}

	e.identities = append(e.identities, corruptedCookieIdentity(knowledge.CorruptedCookieToken, corruptedCookies))

	e.requeueSeenForNewIdentity()
}

func (e *Engine) ensureCorruptedOpaqueCookieIdentity(base model.Request) {
	baseCookies := mergedBaseCookies(base, e.sessionCookies)

	corruptedCookies, ok := corruptOpaqueCookies(baseCookies)
	if !ok {
		return
	}

	for _, id := range e.identities {
		if id.Name == knowledge.CorruptedOpaqueCookieToken {
			return
		}
	}

	if e.debug {
		println("== New synthetic identity discovered:", knowledge.CorruptedOpaqueCookieToken, "==")
	}

	e.identities = append(e.identities, corruptedCookieIdentity(knowledge.CorruptedOpaqueCookieToken, corruptedCookies))

	e.requeueSeenForNewIdentity()
}

func (e *Engine) requeueSeenForNewIdentity() {
	root := e.k.Entity(e.k.Target)

	for _, ent := range e.k.Entities {
		if ent == nil || !ent.State.Seen {
			continue
		}

		if isStaticAsset(ent) || isSessionTerminator(ent.URL) {
			continue
		}

		e.k.PushProbe(root, knowledge.Probe{
			URL:          ent.URL,
			Method:       "GET",
			Reason:       knowledge.ReasonIdentityRefresh,
			Priority:     156,
			IdentityKind: knowledge.ProbeIdentitySynthetic,
		})
	}
}
