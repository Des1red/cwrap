package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/transport"
)

func (e *Engine) runQueuedProbes(base model.Request, url string) error {
	ent := e.k.Entity(url)
	basefp := makeFingerprint(e.baseStatus, e.baseBody)

	// param -> value -> identity -> body/status
	responses := map[string]map[string]map[string][]byte{}
	statuses := map[string]map[string]map[string]int{}

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
			req.Flags.Headers = append(req.Flags.Headers, model.Header{Name: k, Value: v})
		}
		for k, v := range probe.AddQuery {
			req.Flags.Query = append(req.Flags.Query, model.QueryParam{Key: k, Value: v})

			ent.AddParam(k, knowledge.ParamQuery)
			e.k.AddParam(k)
			e.int.ClassifyParam(ent, k)
			ent.Tag(knowledge.SigHasQueryParams)
		}

		// identity dimension
		for _, id := range e.identities {

			reqID := id.Apply(req)

			resp, err := transport.Do(reqID)
			if err != nil {
				continue
			}
			body, err := transport.ReadBody(resp)
			if err != nil {
				continue
			}

			if makeFingerprint(resp.StatusCode, body) != basefp {
				ent.Tag(knowledge.SigStateChanging)
			}

			e.int.Learn(reqID.URL, resp, body)

			storeResponse(
				ent,
				responses,
				statuses,
				probe,
				id.Name,
				resp.StatusCode,
				body,
				e.baseStatus,
				e.baseBody,
				base.URL,
			)
		}

		// reasoning now compares identity differences
		e.analyzeParamBehavior(ent, responses)
		e.analyzeAuthBoundary(ent, statuses)
		e.analyzeOwnership(ent, statuses)
		e.analyzeIDOR(ent, responses, statuses)

		e.Expand(ent)
	}

	return nil
}
