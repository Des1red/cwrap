package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/transport"
)

func (e *Engine) runQueuedProbes(base model.Request, url string, baseStatus int, baseBody []byte) error {
	ent := e.k.Entity(url)
	basefp := makeFingerprint(baseStatus, baseBody)

	responses := map[string]map[string][]byte{}
	statuses := map[string]map[string]int{}

	for ent.ProbeQueue.Len() > 0 {

		probe, _ := ent.ProbeQueue.PopBest()

		key := probe.Key()
		if ent.SeenProbes[key] {
			continue
		}
		ent.SeenProbes[key] = true

		req := base
		req.Method = probe.Method
		req.URL = probe.URL
		req.Flags.Query = nil
		req.Flags.Headers = nil

		for k, v := range probe.Headers {
			req.Flags.Headers = append(req.Flags.Headers, model.Header{
				Name:  k,
				Value: v,
			})
		}

		for k, v := range probe.AddQuery {
			req.Flags.Query = append(req.Flags.Query, model.QueryParam{
				Key:   k,
				Value: v,
			})

			ent.AddParam(k, knowledge.ParamQuery)
			e.k.AddParam(k)
			e.int.ClassifyParam(ent, k)
			ent.Tag(knowledge.SigHasQueryParams)
		}

		// ---- execute request FIRST ----
		resp, err := transport.Do(req)
		if err != nil {
			continue
		}

		body, err := transport.ReadBody(resp)
		if err != nil {
			continue
		}

		// ---- NOW store + lazy baseline ----
		for k, v := range probe.AddQuery {

			if responses[k] == nil {
				responses[k] = map[string][]byte{}
				statuses[k] = map[string]int{}

				// seed baseline for THIS param
				baseVal := extractCurrentValue(base.URL, k)
				if baseVal != "" {
					responses[k][baseVal] = baseBody
					statuses[k][baseVal] = baseStatus
				}
			}

			responses[k][v] = body
			statuses[k][v] = resp.StatusCode
		}

		fp := makeFingerprint(resp.StatusCode, body)
		if fp != basefp {
			ent.Tag(knowledge.SigStateChanging)
		}

		e.int.Learn(req.URL, resp, body)

		// reasoning
		e.analyzeParamBehavior(ent, responses)
		e.analyzeAuthBoundary(ent, statuses)
		e.analyzeOwnership(ent, statuses)
		e.analyzeIDOR(ent, responses, statuses)

		e.Expand(ent)
	}

	return nil
}
