package behavior

import (
	"crypto/sha256"
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/transport"
	"fmt"
	"strings"
)

func cloneRequest(r model.Request) model.Request {
	nr := r

	nr.Flags.Query = append([]model.QueryParam{}, r.Flags.Query...)
	nr.Flags.Headers = append([]model.Header{}, r.Flags.Headers...)

	return nr
}

func (e *Engine) runQueuedProbes(base model.Request, url string) error {
	ent := e.k.Entity(url)
	basefp := makeFingerprint(e.baseStatus, e.baseBody)

	responses := map[string]map[string]map[string][]byte{}
	statuses := map[string]map[string]map[string]int{}

	for ent.ProbeQueue.Len() > 0 {
		identityStatuses := map[string]int{}

		probe, _ := ent.ProbeQueue.PopBest()
		key := probe.Key()

		if ent.SeenProbes[key] {
			continue
		}
		ent.SeenProbes[key] = true

		req := cloneRequest(base)
		req.Method = probe.Method
		req.URL = probe.URL

		// overlay probe headers
		for k, v := range probe.Headers {
			req.Flags.Headers = upsertHeader(req.Flags.Headers, k, v)
		}

		// add probe query params
		for k, v := range probe.AddQuery {
			req.Flags.Query = append(req.Flags.Query, model.QueryParam{Key: k, Value: v})

			if extractCurrentValue(base.URL, k) != "" {
				ent.AddParam(k, knowledge.ParamQuery)
				e.k.AddParam(k)
				e.int.ClassifyParam(ent, k)
				ent.Tag(knowledge.SigHasQueryParams)
			} else {
				ent.AddParam(k, knowledge.ParamInjected)
			}
		}

		probeFP := map[string]string{}
		baseFPStr := fpString(e.baseStatus, e.baseBody)
		if e.debug {
			println("== Running probe:", probe.Method, probe.URL)
			println("   Baseline fingerprint:", baseFPStr)
			println("authBoundaryConfirmed:", e.authBoundaryConfirmed)
		}
		for _, id := range e.identities {

			if e.authBoundaryConfirmed && id.Synthetic {
				continue
			}
			if e.debug {
				println("[PROBE]", probe.URL, "as identity:", id.Name)
			}

			// Start from clean clone
			reqID := cloneRequest(req)
			if id.Synthetic {
				reqID.Flags.Headers = removeAuthHeaders(reqID.Flags.Headers)
			}
			// Apply identity mutation
			reqID = id.Apply(reqID)
			if e.debug {
				println("Headers for", id.Name)
				for _, h := range reqID.Flags.Headers {
					println("   ", h.Name+":", h.Value)
				}
			}

			resp, err := transport.Do(reqID)
			if err != nil {
				continue
			}
			identityStatuses[id.Name] = resp.StatusCode
			if e.debug {
				println("   -> status:", resp.StatusCode)
			}

			body, err := transport.ReadBody(resp)
			if err != nil {
				continue
			}
			extractIdentity(ent, id.Name, resp)
			e.captureSession(ent, id, resp, base.URL)
			probeFP[id.Name] = fpString(resp.StatusCode, body)

			e.int.Learn(reqID.URL, resp, body)

			if makeFingerprint(resp.StatusCode, body) != basefp {
				ent.Tag(knowledge.SigStateChanging)
			}

			storeResponse(ent, responses, statuses, probe, id.Name, resp.StatusCode, body, e.baseStatus, e.baseBody, base.URL)
		}
		e.detectEndpointAuthGate(identityStatuses)
		ref := ""
		for name, fp := range probeFP {
			kid := ent.Identities[name]
			if kid != nil && !kid.SentCreds && fp != "" {
				ref = fp
				break
			}
		}
		if ref == "" {
			ref = baseFPStr
		}

		for name, fp := range probeFP {
			kid := ent.Identities[name]
			if kid == nil {
				continue
			}
			if fp != "" && ref != "" && fp != ref {
				kid.Effective = true
			}
		}

		e.analyzeParamBehavior(ent, responses)
		e.analyzeAuthBoundary(ent, statuses)
		e.analyzeOwnership(ent, statuses)
		e.analyzeIDOR(ent, responses, statuses)
		e.learnProbeImpact(ent, probe, probeFP, ref)
		e.Expand(ent)
	}

	return nil
}
func upsertHeader(h []model.Header, name, value string) []model.Header {
	for i := range h {
		if strings.EqualFold(h[i].Name, name) {
			h[i].Value = value
			return h
		}
	}
	return append(h, model.Header{Name: name, Value: value})
}
func fpString(status int, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%d:%x", status, sum)
}

func (e *Engine) detectEndpointAuthGate(identityStatuses map[string]int) {
	baseline, okB := identityStatuses["baseline"]
	anonymous, okA := identityStatuses["anonymous"]

	if okB && okA && baseline == 200 && (anonymous == 401 || anonymous == 403) {
		if !e.authBoundaryConfirmed {
			e.authBoundaryConfirmed = true
			if e.debug {
				println("== Auth boundary confirmed. Switching to authenticated exploration mode ==")
			}
		}
	}
}
