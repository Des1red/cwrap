package behavior

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"strconv"
)

func (e *Engine) Expand(ent *knowledge.Entity) {

	// no params → discovery probe
	if !ent.SeenSignal(knowledge.SigHasQueryParams) {

		ent.ProbeQueue.Push(knowledge.Probe{
			URL:    ent.URL,
			Method: "GET",
			AddQuery: map[string]string{
				"_cwrap": "1",
			},
			Reason:   knowledge.ReasonParamDiscovery,
			Priority: 50,
		})
		return
	}

	// mutate known params
	for name, p := range ent.Params {

		if p.IDLike && p.Sources[knowledge.ParamQuery] {

			baseVal := extractNumericValue(ent.URL, name)
			if baseVal >= 0 {

				// adjacency (behavior detection)
				try := []int{
					baseVal - 1,
					baseVal + 1,
				}

				for _, v := range try {
					if v < 0 {
						continue
					}

					ent.ProbeQueue.Push(knowledge.Probe{
						URL:      ent.URL,
						Method:   "GET",
						AddQuery: map[string]string{name: strconv.Itoa(v)},
						Reason:   knowledge.ReasonIDAdjacency,
						Priority: 95,
					})
				}
			}
		}
	}

	// ownership probes
	if ent.SeenSignal(knowledge.SigObjectOwnership) {
		e.expandIdentityProbes(ent)
	}
	// enumeration is a separate strategy
	e.expandIDEnumeration(ent)
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

func (e *Engine) expandIDEnumeration(ent *knowledge.Entity) {

	for name, p := range ent.Params {

		if !p.IDLike {
			continue
		}

		// extract current value from URL
		baseVal := extractCurrentValue(ent.URL, name)
		if baseVal == "" {
			continue
		}

		id, err := strconv.Atoi(baseVal)
		if err != nil {
			continue
		}

		// probe nearby objects
		tests := []int{id + 1, id + 2, id + 3}

		for _, v := range tests {

			ent.ProbeQueue.Push(knowledge.Probe{
				URL:    ent.URL,
				Method: "GET",
				AddQuery: map[string]string{
					name: strconv.Itoa(v),
				},
				Reason:   knowledge.ReasonIDEnum,
				Priority: 90,
			})
		}
	}
}

func (e *Engine) expandIdentityProbes(ent *knowledge.Entity) {

	// baseline request but without auth hints
	ent.ProbeQueue.Push(knowledge.Probe{
		URL:      ent.URL,
		Method:   "GET",
		Headers:  map[string]string{},
		Reason:   knowledge.ReasonIdentityProbe,
		Priority: 120,
	})

	// fake auth header
	ent.ProbeQueue.Push(knowledge.Probe{
		URL:    ent.URL,
		Method: "GET",
		Headers: map[string]string{
			"Authorization": "Bearer invalid",
		},
		Reason:   knowledge.ReasonIdentityProbe,
		Priority: 120,
	})

	// role confusion attempts
	ent.ProbeQueue.Push(knowledge.Probe{
		URL:    ent.URL,
		Method: "GET",
		Headers: map[string]string{
			"X-User-Role": "admin",
		},
		Reason:   knowledge.ReasonIdentityProbe,
		Priority: 120,
	})

	ent.ProbeQueue.Push(knowledge.Probe{
		URL:    ent.URL,
		Method: "GET",
		Headers: map[string]string{
			"X-Forwarded-User": "admin",
		},
		Reason:   knowledge.ReasonIdentityProbe,
		Priority: 120,
	})
}
