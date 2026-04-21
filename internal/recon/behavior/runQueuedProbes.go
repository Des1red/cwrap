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
	// Root entity owns the scheduler queue
	root := e.k.Entity(url)

	for root.ProbeQueue.Len() > 0 {
		probe, ok := root.ProbeQueue.PopBest()
		if !ok {
			break
		}

		// Dedupe at scheduler level (root), because the queue lives here
		key := probe.Key()
		if root.SeenProbes[key] {
			continue
		}
		root.SeenProbes[key] = true

		// Target entity is where state MUST be attributed
		target := e.k.Entity(probe.URL)

		// Mark target as seen the first time we actually execute something against it
		target.State.Seen = true
		if probe.Reason == knowledge.ReasonPathIDProbe && !target.State.OrganicallyDiscovered {
			target.State.IsPathVariant = true
		}
		// Per-probe maps (so analyzers don't mix endpoints)
		responses := map[string]map[string]map[string][]byte{}
		statuses := map[string]map[string]map[string]int{}

		req := cloneRequest(base)
		req.Method = probe.Method
		req.URL = probe.URL

		// overlay probe headers
		for k, v := range probe.Headers {
			req.Flags.Headers = upsertHeader(req.Flags.Headers, k, v)
		}

		// add probe query params (attribute params to TARGET, not root)
		for k, v := range probe.AddQuery {
			req.Flags.Query = append(req.Flags.Query, model.QueryParam{Key: k, Value: v})

			// IMPORTANT: decide source relative to the target URL, not base.URL
			if extractCurrentValue(probe.URL, k) != "" {
				target.AddParam(k, knowledge.ParamQuery)
				e.k.AddParam(k)
				e.int.ClassifyParam(target, k)
				target.Tag(knowledge.SigHasQueryParams)
			} else {
				target.AddParam(k, knowledge.ParamInjected)
				p := target.Params[k]
				if p != nil && p.DiscoveryReason == "" {
					p.DiscoveryReason = probe.Reason
				}
				e.int.ClassifyParam(target, k)
			}
		}
		for k := range probe.PathParams {
			target.AddParam(k, knowledge.ParamPath)
			e.k.AddParam(k)
			e.int.ClassifyParam(target, k)
			p := target.Params[k]
			if p != nil && p.DiscoveryReason == "" {
				p.DiscoveryReason = probe.Reason
			}
		}

		identityStatuses := map[string]int{}
		probeFP := map[string]string{}

		if e.debug {
			println("== Running probe:", probe.Method, probe.URL)
			println("authBoundaryConfirmed:", e.authBoundaryConfirmed)
		}

		executed := false

		for _, id := range e.identities {
			if e.authBoundaryConfirmed && id.Synthetic {
				continue
			}
			if e.debug {
				println("[PROBE]", probe.URL, "as identity:", id.Name)
			}

			reqID := cloneRequest(req)
			if id.Synthetic {
				reqID.Flags.Headers = removeAuthHeaders(reqID.Flags.Headers)
			}
			reqID = id.Apply(reqID)

			resp, err := transport.Do(reqID)
			if err != nil {
				continue
			}

			// ProbeCount belongs to TARGET endpoint
			if !executed {
				target.State.ProbeCount++
				executed = true
			}

			if methodAllowed(resp.StatusCode) {
				target.AddMethod(probe.Method)
			}
			identityStatuses[id.Name] = resp.StatusCode

			body, err := transport.ReadBody(resp)
			if err != nil {
				continue
			}

			// Identity/session attribution TARGET-scoped
			extractIdentity(target, id.Name, resp)
			e.captureSession(target, id, resp, base.URL)

			probeFP[id.Name] = fpString(resp.StatusCode, body)
			e.int.Learn(reqID.URL, resp, body)

			storeResponse(target, responses, statuses, probe, id.Name, resp.StatusCode, body, e.baseStatus, e.baseBody, base.URL, e.k)
		}

		// auth gate detection is GLOBAL behavior mode, keep it as-is
		e.detectEndpointAuthGate(identityStatuses, probeFP)
		// entity-level role boundary detection
		// runs directly off identity statuses, not param maps
		e.detectRoleBoundary(target, identityStatuses)
		e.detectAuthBoundary(target, identityStatuses)

		// Choose a reference fingerprint (prefer a no-creds identity if available)
		ref := ""
		for name, fp := range probeFP {
			kid := target.Identities[name]
			if kid != nil && !kid.SentCreds && fp != "" {
				ref = fp
				break
			}
		}
		if ref == "" {
			// fallback: pick any fp
			for _, fp := range probeFP {
				if fp != "" {
					ref = fp
					break
				}
			}
		}

		// Mark effective identities for THIS TARGET endpoint
		for name, fp := range probeFP {
			kid := target.Identities[name]
			if kid == nil {
				continue
			}
			if fp != "" && ref != "" && fp != ref {
				kid.Effective = true
				// tag "state changing" per probe
				target.Tag(knowledge.SigStateChanging)
			}
		}

		// Run analyzers on TARGET endpoint only (per-probe maps)

		// accumulated (needs full history to detect structural changes across values)
		e.analyzeParamBehavior(target, target.AccumResponses)
		e.analyzeAuthBoundary(target, statuses)
		e.analyzeOwnership(target, statuses)
		e.analyzeIDOR(target, responses, statuses)
		e.analyzeIDOR(target, target.AccumResponses, target.AccumStatuses)
		e.analyzeMethods(target)
		e.analyzeCredentiallessIssuance(target)
		// for path id probes, also run param behavior on the source entity
		// so it sees all variant values accumulated across probes
		if probe.Reason == knowledge.ReasonPathIDProbe && probe.SourceURL != "" {
			sourceEnt := e.k.Entity(probe.SourceURL)
			e.analyzeParamBehavior(sourceEnt, sourceEnt.AccumResponses)
			e.analyzeOwnership(sourceEnt, sourceEnt.AccumStatuses)
			e.analyzeIDOR(sourceEnt, sourceEnt.AccumResponses, sourceEnt.AccumStatuses)
		}
		// Learn + expand TARGET (not root)
		e.learnProbeImpact(target, probe, probeFP, ref)
		e.Expand(target)
		// propagate sub-probes from non-root target entities to root queue
		// if target IS root, Expand already pushed to root.ProbeQueue directly
		if target != root {
			for target.ProbeQueue.Len() > 0 {
				p, ok := target.ProbeQueue.PopBest()
				if ok {
					e.k.PushProbe(root, p)
				}
			}
		}
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

func methodAllowed(status int) bool {

	switch status {

	case 405, 501:
		return false

	case 200, 201, 202, 204,
		301, 302, 303, 304, 307, 308,
		400, 401, 403:
		return true

	default:
		return false
	}
}
