package behavior

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"strconv"
	"strings"
)

func (e *Engine) Expand(ent *knowledge.Entity) {

	if ent.State.ProbeCount > 50 {
		return
	}

	e.expandMethods(ent)

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

	should := false

	if ent.SeenSignal(knowledge.SigAuthBoundary) ||
		ent.SeenSignal(knowledge.SigObjectOwnership) ||
		ent.SeenSignal(knowledge.SigPossibleIDOR) {
		should = true
	}

	for _, p := range ent.Params {
		if p.IDLike {
			should = true
			break
		}
	}

	if !should {
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

	key := p.Key()

	if ent.SeenProbes[key] {
		return
	}

	ent.ProbeQueue.Push(p)
}

func (e *Engine) expandMethods(ent *knowledge.Entity) {

	if ent.State.ProbeCount > 3 {
		return
	}

	if len(ent.HTTP.Methods) > 1 {
		return
	}

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
}
