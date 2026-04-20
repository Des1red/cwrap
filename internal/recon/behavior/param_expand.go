package behavior

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func isJSEntity(ent *knowledge.Entity) bool {
	u := strings.ToLower(ent.URL)
	return strings.HasSuffix(u, ".js") ||
		strings.Contains(u, ".js?") ||
		strings.Contains(u, ".js#")
}

func (e *Engine) Expand(ent *knowledge.Entity) {

	if ent.State.ProbeCount > 50 {
		return
	}

	// skip param discovery and mutation on static JS files
	if isJSEntity(ent) {
		e.expandMethods(ent)
		e.expandIdentity(ent)
		return
	}

	e.expandMethods(ent)
	e.expandPathIDs(ent)

	meaningful := false
	for _, p := range ent.Params {
		if p.LikelyObjectAccess || p.Enumerable || p.AuthBoundary || p.OwnershipBoundary {
			meaningful = true
			break
		}
	}

	if !meaningful {
		e.expandDiscovery(ent)
	}

	e.expandMutation(ent)
	e.expandIdentity(ent)
	e.expandEnumeration(ent)
}

func extractNumericValue(raw, key string) int {

	u, err := url.Parse(raw)
	if err != nil {
		return -1
	}

	v := u.Query().Get(key)
	if v == "" {
		return -1
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}

	return n
}

func (e *Engine) expandDiscovery(ent *knowledge.Entity) {
	if ent.State.DiscoveryProbed {
		return
	}
	ent.State.DiscoveryProbed = true
	u, err := url.Parse(ent.URL)
	if err != nil {
		return
	}

	segments := strings.Split(strings.Trim(u.Path, "/"), "/")

	for _, s := range segments {
		if len(s) < 3 {
			continue
		}
		if _, err := strconv.Atoi(s); err == nil {
			continue // skip numeric path parts
		}

		e.pushProbe(ent, knowledge.Probe{
			URL:    ent.URL,
			Method: "GET",
			AddQuery: map[string]string{
				s: "1",
			},
			Reason:   knowledge.ReasonParamDiscovery,
			Priority: 50,
		})
	}

	// small universal fallback
	common := []string{"id", "user", "page", "q"}

	for _, p := range common {
		e.pushProbe(ent, knowledge.Probe{
			URL:    ent.URL,
			Method: "GET",
			AddQuery: map[string]string{
				p: "1",
			},
			Reason:   knowledge.ReasonParamDiscovery,
			Priority: 40,
		})
	}
}

func (e *Engine) expandMutation(ent *knowledge.Entity) {

	for name, p := range ent.Params {
		if !p.IDLike {
			continue
		}

		if !p.Sources[knowledge.ParamQuery] && !p.LikelyObjectAccess && !p.Enumerable {
			continue
		}

		baseVal := extractNumericValue(ent.URL, name)
		if baseVal < 0 {
			continue
		}

		// Base mutations (always)
		tests := []string{
			strconv.Itoa(baseVal - 1),
			strconv.Itoa(baseVal + 1),
			"0",
			"1",
			"-1",
		}

		// Adaptive: if param is "hot", expand more (still controlled)
		if p.Interest >= 1 {
			tests = append(tests, "999999", "", "null", "undefined")
		}
		if p.Interest >= 3 {
			tests = append(tests,
				strconv.Itoa(baseVal+2),
				strconv.Itoa(baseVal+5),
				"2147483647", // int32 max
				"4294967295", // uint32 max
			)
		}

		priority := 100
		if p.Interest >= 1 {
			priority = 120
		}
		if p.Interest >= 3 {
			priority = 140
		}

		for _, v := range tests {
			e.pushProbe(ent, knowledge.Probe{
				URL:    ent.URL,
				Method: "GET",
				AddQuery: map[string]string{
					name: v,
				},
				Reason:   knowledge.ReasonIDAdjacency,
				Priority: priority,
			})
		}
	}
}

func (e *Engine) expandIdentity(ent *knowledge.Entity) {

	// auth signals on this specific entity
	hasAuthSignal := ent.SeenSignal(knowledge.SigAuthBoundary) ||
		ent.SeenSignal(knowledge.SigObjectOwnership) ||
		ent.SeenSignal(knowledge.SigPossibleIDOR)

	// entity has seen auth-like behavior (server issued cookies, auth header observed)
	hasAuthBehavior := ent.HTTP.AuthLikely

	// engine confirmed a boundary globally (any endpoint required auth)
	globalBoundary := e.authBoundaryConfirmed

	if !hasAuthSignal && !hasAuthBehavior && !globalBoundary {
		return
	}

	// baseline (no auth hints)
	e.pushProbe(ent, knowledge.Probe{
		URL:      ent.URL,
		Method:   "GET",
		Headers:  map[string]string{},
		Reason:   knowledge.ReasonIdentityProbe,
		Priority: 150,
	})

	// invalid bearer
	e.pushProbe(ent, knowledge.Probe{
		URL:    ent.URL,
		Method: "GET",
		Headers: map[string]string{
			"Authorization": "Bearer invalid",
		},
		Reason:   knowledge.ReasonIdentityProbe,
		Priority: 150,
	})

	// role confusion attempts
	roleHeaders := []string{"X-User-Role", "X-Forwarded-User"}

	for _, h := range roleHeaders {
		e.pushProbe(ent, knowledge.Probe{
			URL:    ent.URL,
			Method: "GET",
			Headers: map[string]string{
				h: "admin",
			},
			Reason:   knowledge.ReasonIdentityProbe,
			Priority: 150,
		})
	}
}

func (e *Engine) expandEnumeration(ent *knowledge.Entity) {

	for name, p := range ent.Params {

		if !p.IDLike || !p.Enumerable {
			continue
		}

		baseVal := extractCurrentValue(ent.URL, name)
		if baseVal == "" {
			continue
		}

		id, err := strconv.Atoi(baseVal)
		if err != nil {
			continue
		}

		tests := []int{id + 1, id + 2}

		// Adaptive depth
		if p.Interest >= 1 {
			tests = append(tests, id+5, id+10)
		}
		if p.Interest >= 3 {
			tests = append(tests, id+25, id+50)
		}

		priority := 80
		if p.Interest >= 1 {
			priority = 100
		}
		if p.Interest >= 3 {
			priority = 120
		}

		for _, v := range tests {
			e.pushProbe(ent, knowledge.Probe{
				URL:    ent.URL,
				Method: "GET",
				AddQuery: map[string]string{
					name: strconv.Itoa(v),
				},
				Reason:   knowledge.ReasonIDEnum,
				Priority: priority,
			})
		}
	}
}

func (e *Engine) pushProbe(ent *knowledge.Entity, p knowledge.Probe) {
	e.k.PushProbe(ent, p)
}

func (e *Engine) expandMethods(ent *knowledge.Entity) {
	// only skip if we've already done a full method sweep
	if ent.State.MethodProbed {
		return
	}

	// skip method sweep on path-variant entities — they're probe-generated URLs
	// not real discovered endpoints, so sweeping methods is wasteful noise
	if ent.State.IsPathVariant {
		ent.State.MethodProbed = true
		return
	}
	// don't re-probe methods we already know about
	methods := []string{
		"GET",
		"POST",
		"PUT",
		"PATCH",
		"DELETE",
		"OPTIONS",
		"HEAD",
	}

	for _, m := range methods {
		if ent.HTTP.Methods[m] {
			continue
		}
		e.pushProbe(ent, knowledge.Probe{
			URL:      ent.URL,
			Method:   m,
			Reason:   knowledge.ReasonMethodProbe,
			Priority: 60,
		})
	}

	ent.State.MethodProbed = true
}

var uuidRe = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
)

func looksLikePathID(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}
	return uuidRe.MatchString(strings.ToLower(s))
}

func replacePathSegment(u *url.URL, idx int, val string) string {
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if idx < 0 || idx >= len(segments) {
		return u.String()
	}
	newSegs := make([]string, len(segments))
	copy(newSegs, segments)
	newSegs[idx] = val
	newU := *u
	newU.Path = "/" + strings.Join(newSegs, "/")
	return newU.String()
}

func pathTemplate(u *url.URL) string {
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, seg := range segments {
		if looksLikePathID(seg) {
			segments[i] = "{id}"
		}
	}
	return "/" + strings.Join(segments, "/")
}

func (e *Engine) expandPathIDs(ent *knowledge.Entity) {
	if ent.State.PathIDProbed {
		return
	}
	ent.State.PathIDProbed = true
	if ent.State.ProbeCount > 50 {
		return
	}

	u, err := url.Parse(ent.URL)
	if err != nil {
		return
	}

	rawPath := strings.Trim(u.Path, "/")
	if rawPath == "" {
		return
	}

	tmpl := pathTemplate(u)
	if _, seen := e.probedPathTemplates[tmpl]; seen {
		return
	}
	e.probedPathTemplates[tmpl] = struct{}{}

	segments := strings.Split(rawPath, "/")

	for i, seg := range segments {
		if !looksLikePathID(seg) {
			continue
		}

		// derive a meaningful param name from the parent segment
		name := "id"
		if i > 0 {
			parent := strings.ToLower(segments[i-1])
			if strings.HasSuffix(parent, "s") && len(parent) > 2 {
				parent = parent[:len(parent)-1]
			}
			name = parent + "_id"
		}

		// register param
		ent.AddParam(name, knowledge.ParamPath)
		e.k.AddParam(name)
		e.int.ClassifyParam(ent, name)
		ent.Tag(knowledge.SigIDLikeParam)

		// base mutations only — fixed depth, no adaptive expansion
		tests := []string{"0", "1", "-1"}
		if id, err := strconv.Atoi(seg); err == nil {
			tests = append(tests,
				strconv.Itoa(id-1),
				strconv.Itoa(id+1),
			)
		} else {
			tests = append(tests, "00000000-0000-0000-0000-000000000000")
		}

		for _, v := range tests {
			newURL := replacePathSegment(u, i, v)
			e.pushProbe(ent, knowledge.Probe{
				URL:           newURL,
				Method:        "GET",
				PathParams:    map[string]string{name: v},
				PathParamBase: map[string]string{name: seg},
				Reason:        knowledge.ReasonPathIDProbe,
				Priority:      100,
				Created:       time.Now(),
				SourceURL:     ent.URL,
			})
		}
	}
}
