package behavior

import (
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

func upsertHeader(h []model.Header, name, value string) []model.Header {
	for i := range h {
		if strings.EqualFold(h[i].Name, name) {
			h[i].Value = value
			return h
		}
	}
	return append(h, model.Header{Name: name, Value: value})
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

func (e *Engine) runQueuedProbes(base model.Request, url string) error {
	root := e.k.Entity(url)

	for root.ProbeQueue.Len() > 0 {
		probe, ok := root.ProbeQueue.PopBest()
		if !ok {
			break
		}

		key := probe.Key()
		if root.SeenProbes[key] {
			continue
		}
		root.SeenProbes[key] = true

		target := e.k.Entity(probe.URL)
		if len(probe.AddQuery) > 0 && target != root && !target.State.OrganicallyDiscovered {
			target.State.IsParamVariant = true
		}
		target.State.Seen = true
		if probe.Reason == knowledge.ReasonPathIDProbe && !target.State.OrganicallyDiscovered {
			target.State.IsPathVariant = true
		}
		if !target.State.IsParamVariant {
			e.registerURLQueryParams(target)
		}
		req := e.buildProbeRequest(base, probe)

		responses, statuses, identityStatuses, probeFP, evidence := e.executeProbeIdentities(req, probe, target, root, base)
		e.detectEndpointAuthGate(identityStatuses, probeFP)
		e.detectRoleBoundary(target, identityStatuses)
		e.detectAuthBoundary(target, identityStatuses)
		e.detectPublicAccess(target, identityStatuses, probeFP)

		if len(identityStatuses) > 0 {
			e.classifyProbeParams(probe, target)
		}

		reference, hasReference := e.resolveProbeReference(
			target,
			probeFP,
			evidence,
		)

		e.markEffectiveIdentities(
			target,
			probeFP,
			reference,
			hasReference,
		)

		if !target.State.IsSPAFallback {
			e.analyzeAbnormalResponses(
				target,
				probeFP,
				evidence,
				reference,
				hasReference,
			)
			e.runProbeAnalyzers(
				target,
				probe,
				responses,
				statuses,
			)
			e.learnProbeImpact(
				target,
				probe,
				probeFP,
				reference,
				hasReference,
			)
		}

		e.Expand(target)

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

func (e *Engine) buildProbeRequest(base model.Request, probe knowledge.Probe) model.Request {
	req := cloneRequest(base)
	req.Method = probe.Method
	req.URL = probe.URL
	req.Flags.Body = ""

	for k, v := range probe.Headers {
		req.Flags.Headers = upsertHeader(req.Flags.Headers, k, v)
	}

	if len(probe.Body) > 0 {
		req.Flags.Body = string(probe.Body)
		if probe.ContentType != "" {
			req.Flags.Headers = upsertHeader(req.Flags.Headers, "Content-Type", probe.ContentType)
		}
	}

	for k, v := range probe.AddQuery {
		req.Flags.Query = append(req.Flags.Query, model.QueryParam{Key: k, Value: v})
	}

	return req
}

func (e *Engine) executeProbeIdentities(
	req model.Request,
	probe knowledge.Probe,
	target, root *knowledge.Entity,
	base model.Request,
) (
	responses map[string]map[string]map[string][]byte,
	statuses map[string]map[string]map[string]int,
	identityStatuses map[string]int,
	probeFP map[string]string,
	evidence map[string]probeResponseEvidence,
) {
	responses = map[string]map[string]map[string][]byte{}
	statuses = map[string]map[string]map[string]int{}
	identityStatuses = map[string]int{}
	probeFP = map[string]string{}
	evidence = map[string]probeResponseEvidence{}

	if e.debug {
		println("== Running probe:", probe.Method, probe.URL)
		println("authBoundaryConfirmed:", e.authBoundaryConfirmed)
	}

	target.State.ProbeCount++
	suppressSynthetic := e.authBoundaryConfirmed &&
		(probe.Reason == knowledge.ReasonParamDiscovery ||
			probe.Reason == knowledge.ReasonIDAdjacency ||
			probe.Reason == knowledge.ReasonIDEnum ||
			probe.Reason == knowledge.ReasonLinkProbe)

	for _, id := range e.identities {
		switch probe.IdentityKind {
		case knowledge.ProbeIdentitySynthetic:
			if !id.Synthetic {
				continue
			}
		case knowledge.ProbeIdentityLive:
			if id.Synthetic {
				continue
			}
		}

		if probe.IdentityKind != knowledge.ProbeIdentitySynthetic && suppressSynthetic && id.Synthetic {
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

		if probe.Method == "POST" || probe.Method == "PUT" ||
			probe.Method == "PATCH" || probe.Method == "DELETE" {
			injectCSRFHeader(&reqID, target, id.Name, e.sessionCookies)
		}

		resp, err := transport.Do(reqID)
		if err != nil {
			if e.debug {
				fmt.Printf("[ERROR] %s %s as %s: %v\n", probe.Method, probe.URL, id.Name, err)
			}
			continue
		}

		if methodAllowed(resp.StatusCode) && probe.Method != "OPTIONS" {
			target.AddMethod(probe.Method)
		}
		identityStatuses[id.Name] = resp.StatusCode

		body, err := transport.ReadBody(resp)
		if err != nil {
			continue
		}

		isFallback := false
		if target != root && !isBootstrapLikeURL(reqID.URL) {
			pageFP := buildPageFP(reqID.URL, resp, body)
			if looksLikeFallbackPage(pageFP, e.basePageFP) {
				target.State.IsSPAFallback = true
				isFallback = true
			}
		}

		probeFP[id.Name] = fpString(resp.StatusCode, body)
		target.AddProbeLog(knowledge.ProbeLogEntry{
			URL:          probeLogURL(reqID),
			Method:       reqID.Method,
			Reason:       probe.Reason,
			Identity:     id.Name,
			IdentityKind: probe.IdentityKind,
			Status:       resp.StatusCode,
			FP:           probeFP[id.Name],
			Location:     resp.Header.Get("Location"),
		})

		if isFallback {
			continue
		}

		evidence[id.Name] = probeResponseEvidence{
			URL:         probeLogURL(reqID),
			Method:      reqID.Method,
			Body:        body,
			ContentType: resp.Header.Get("Content-Type"),
			Status:      resp.StatusCode,
		}

		extractIdentity(target, id.Name, resp, id.Synthetic)
		e.captureSession(target, id, resp, base.URL)
		if !id.Synthetic {
			e.ensureCorruptedCookieIdentity(base)
			e.ensureCorruptedOpaqueCookieIdentity(base)
		}

		e.int.Learn(reqID.URL, resp, body)

		storeResponse(target, responses, statuses, probe, id.Name, resp.StatusCode, body, e.baseStatus, e.baseBody, base.URL, e.k, e.debug)
	}

	return
}

func (e *Engine) classifyProbeParams(probe knowledge.Probe, target *knowledge.Entity) {
	for k := range probe.AddQuery {
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
}

func (e *Engine) resolveProbeReference(
	target *knowledge.Entity,
	probeFP map[string]string,
	evidence map[string]probeResponseEvidence,
) (probeReference, bool) {
	// Prefer a response from an identity that sent no credentials.
	for _, id := range e.identities {
		fp := probeFP[id.Name]
		ev, ok := evidence[id.Name]

		if fp == "" || !ok {
			continue
		}

		kid := target.Identities[id.Name]
		if kid != nil && !kid.SentCreds {
			return probeReference{
				Identity:    id.Name,
				Fingerprint: fp,
				Evidence:    ev,
			}, true
		}
	}

	// Fall back to the first executed identity with complete evidence.
	for _, id := range e.identities {
		fp := probeFP[id.Name]
		ev, ok := evidence[id.Name]

		if fp == "" || !ok {
			continue
		}

		return probeReference{
			Identity:    id.Name,
			Fingerprint: fp,
			Evidence:    ev,
		}, true
	}

	return probeReference{}, false
}

func (e *Engine) markEffectiveIdentities(
	target *knowledge.Entity,
	probeFP map[string]string,
	reference probeReference,
	hasReference bool,
) {
	if !hasReference {
		return
	}

	for name, fp := range probeFP {
		kid := target.Identities[name]
		if kid == nil {
			continue
		}

		if fp != "" && fp != reference.Fingerprint {
			kid.Effective = true
			target.Tag(knowledge.SigStateChanging)
		}
	}
}

func (e *Engine) runProbeAnalyzers(
	target *knowledge.Entity,
	probe knowledge.Probe,
	responses map[string]map[string]map[string][]byte,
	statuses map[string]map[string]map[string]int,
) {

	e.analyzeParamBehavior(target, target.AccumResponses)
	e.analyzeAuthBoundary(target, statuses)
	e.analyzeOwnership(target, statuses)
	e.analyzeObjectAccessSurface(target, target.AccumStatuses)
	e.analyzeIDOR(target, responses, statuses)
	e.analyzeIDOR(target, target.AccumResponses, target.AccumStatuses)
	e.analyzeMethods(target)
	e.analyzeCredentiallessIssuance(target)
	e.analyzeTokenValidation(target)

	promoteRealInputIDOverResponseID(target)
	demoteResponseDerivedIDORIfRealInputExists(target)

	if probe.Reason == knowledge.ReasonPathIDProbe && probe.SourceURL != "" {
		sourceEnt := e.k.Entity(probe.SourceURL)
		e.analyzeParamBehavior(sourceEnt, sourceEnt.AccumResponses)
		e.analyzeOwnership(sourceEnt, sourceEnt.AccumStatuses)
		e.analyzeObjectAccessSurface(sourceEnt, sourceEnt.AccumStatuses)
		e.analyzeIDOR(sourceEnt, sourceEnt.AccumResponses, sourceEnt.AccumStatuses)

		promoteRealInputIDOverResponseID(sourceEnt)
		demoteResponseDerivedIDORIfRealInputExists(sourceEnt)
	}
}
