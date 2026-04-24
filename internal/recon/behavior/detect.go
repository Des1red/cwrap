package behavior

import "cwrap/internal/recon/knowledge"

func (e *Engine) detectEndpointAuthGate(identityStatuses map[string]int, probeFP map[string]string) {
	baseline, okB := identityStatuses[knowledge.LiveSession]
	if !okB {
		return
	}

	// treat any 2xx or 3xx as baseline succeeded
	baselineSucceeded := baseline >= 200 && baseline < 400

	if !baselineSucceeded {
		return
	}

	baseFP := probeFP[knowledge.LiveSession]

	for name, status := range identityStatuses {
		if name == knowledge.LiveSession {
			continue
		}

		// hard signal: baseline succeeds, any non-baseline identity gets denied
		if status == 401 || status == 403 {
			e.raiseAuthConfidence(10)
			return
		}

		// soft signal: same status family but different response fingerprint
		// catches empty-body responses, stripped data, soft redirects
		if baseFP != "" {
			idFP := probeFP[name]
			if idFP != "" && idFP != baseFP {
				e.raiseAuthConfidence(3)
			}
		}
	}
}

func (e *Engine) detectAuthBoundary(ent *knowledge.Entity, identityStatuses map[string]int) {
	hasAuthedSuccess := false
	hasUnauthDenied := false

	for idName, status := range identityStatuses {
		id := ent.Identities[idName]
		if id == nil {
			continue
		}
		if status == 200 && id.SentCreds {
			hasAuthedSuccess = true
		}
		if (status == 401 || status == 403) && !id.SentCreds {
			hasUnauthDenied = true
		}
	}

	if hasAuthedSuccess && hasUnauthDenied {
		ent.Tag(knowledge.SigAuthBoundary)
	}
}

func (e *Engine) detectPublicAccess(ent *knowledge.Entity, identityStatuses map[string]int) {
	// public = anonymous gets 200 without sending any credentials
	id := ent.Identities[knowledge.Anonymous]
	if id == nil {
		return
	}
	if id.Kind == knowledge.IdentityNone && identityStatuses[knowledge.Anonymous] == 200 {
		ent.Tag(knowledge.SigPublicAccess)
	}
}

func (e *Engine) detectRoleBoundary(ent *knowledge.Entity, identityStatuses map[string]int) {
	for idName, status := range identityStatuses {
		if status != 401 && status != 403 {
			continue
		}

		id := ent.Identities[idName]
		if e.debug {
			println("[RB DEBUG]", idName, "status:", status)
			if id != nil {
				println("[RB DEBUG]", idName, "SentCreds:", id.SentCreds)
			} else {
				println("[RB DEBUG]", idName, "identity is nil")
			}
		}

		if id != nil && id.SentCreds {
			ent.Tag(knowledge.SigRoleBoundary)
			return
		}
	}
}

func (e *Engine) raiseAuthConfidence(delta int) {
	e.authConfidence += delta
	if e.authConfidence >= 10 && !e.authBoundaryConfirmed {
		e.authBoundaryConfirmed = true
		if e.debug {
			println("== Auth boundary confirmed (confidence:", e.authConfidence, ") ==")
		}
	}
}
