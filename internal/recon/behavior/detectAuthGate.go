package behavior

func (e *Engine) detectEndpointAuthGate(identityStatuses map[string]int, probeFP map[string]string) {
	baseline, okB := identityStatuses["baseline"]
	if !okB {
		return
	}

	// treat any 2xx or 3xx as baseline succeeded
	baselineSucceeded := baseline >= 200 && baseline < 400

	if !baselineSucceeded {
		return
	}

	baseFP := probeFP["baseline"]

	for name, status := range identityStatuses {
		if name == "baseline" {
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

func (e *Engine) raiseAuthConfidence(delta int) {
	e.authConfidence += delta
	if e.authConfidence >= 10 && !e.authBoundaryConfirmed {
		e.authBoundaryConfirmed = true
		if e.debug {
			println("== Auth boundary confirmed (confidence:", e.authConfidence, ") ==")
		}
	}
}
