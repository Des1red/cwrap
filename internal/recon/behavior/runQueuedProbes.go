package behavior

import (
	"crypto/sha256"
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/transport"
	"fmt"
	"strings"
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
		// inject session cookies into this probe
		for name, value := range ent.SessionCookies {
			req.Flags.Headers = upsertHeader(
				req.Flags.Headers,
				"Cookie",
				name+"="+value,
			)
		}
		req.Method = probe.Method
		req.URL = probe.URL

		// start from baseline identity
		req.Flags.Query = append([]model.QueryParam{}, base.Flags.Query...)
		req.Flags.Headers = append([]model.Header{}, base.Flags.Headers...)
		// per-probe: fingerprint by identity
		probeFP := map[string]string{}
		// also compute baseline fp string once
		baseFPStr := fpString(e.baseStatus, e.baseBody)

		// overlay probe headers (override by name)
		for k, v := range probe.Headers {
			req.Flags.Headers = upsertHeader(req.Flags.Headers, k, v)
		}

		// add probe query params
		for k, v := range probe.AddQuery {
			req.Flags.Query = append(req.Flags.Query, model.QueryParam{Key: k, Value: v})

			// classify source correctly (your existing logic)
			if extractCurrentValue(base.URL, k) != "" {
				ent.AddParam(k, knowledge.ParamQuery)
				e.k.AddParam(k)
				e.int.ClassifyParam(ent, k)
				ent.Tag(knowledge.SigHasQueryParams)
			} else {
				ent.AddParam(k, knowledge.ParamInjected)
			}
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
			captureSession(ent, resp, base.URL)
			probeFP[id.Name] = fpString(resp.StatusCode, body)

			e.int.Learn(reqID.URL, resp, body)
			extractIdentity(ent, id.Name, resp)
			if makeFingerprint(resp.StatusCode, body) != basefp {
				ent.Tag(knowledge.SigStateChanging)
			}
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
		// Choose a reference fp for "no-credentials" (generic, not name-based).
		ref := ""
		for name, fp := range probeFP {
			kid := ent.Identities[name]
			if kid != nil && !kid.SentCreds && fp != "" {
				ref = fp
				break
			}
		}
		if ref == "" {
			// No no-cred identity exists; fall back to true baseline behavior.
			ref = baseFPStr
		}

		// Mark identities effective if they differ from the reference behavior.
		for name, fp := range probeFP {
			kid := ent.Identities[name]
			if kid == nil {
				continue
			}
			if fp != "" && ref != "" && fp != ref {
				kid.Effective = true
			}
		}
		// reasoning now compares identity differences
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
